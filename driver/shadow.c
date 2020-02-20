/*
 * UIO shadow_proc Driver
 *
 * (C) 2009 Cam Macdonell
 * (C) 2017 Henning Schild
 * based on Hilscher CIF card driver (C) 2007 Hans J. Koch <hjk@linutronix.de>
 *
 * Licensed under GPL version 2 only.
 *
 */

#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include <linux/virtio_ring.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/poll.h>

#define DRV_NAME "shadow-process"

#define IntrStatus 0x04
#define IntrMask 0x00

#define shadow_proc_CFG_VENDOR_CAP 0x40
#define shadow_proc_CFG_VENDOR_LEN 20
#define shadow_proc_CFG_MSIX_CAP   (shadow_proc_CFG_VENDOR_CAP+shadow_proc_CFG_VENDOR_LEN)
#define shadow_proc_CFG_SHMEM_ADDR (shadow_proc_CFG_VENDOR_CAP + 4)
#define shadow_proc_CFG_SHMEM_SIZE (shadow_proc_CFG_VENDOR_CAP + 12)

#define JAILHOUSE_CFG_FLAGS        0x3
#define JAILHOUSE_CFG_SHMEM_ADDR1    0x14
#define JAILHOUSE_CFG_SHMEM_SIZE1    0x1c
#define JAILHOUSE_CFG_SHMEM_ADDR2    0x24
#define JAILHOUSE_CFG_SHMEM_SIZE2    0x2c

#define SHADOW_PROC_CFGFLAG_INTX        0x1

#define SHADOW_PROC_RSTATE_WRITE_ENABLE    (1ULL << 0)
#define SHADOW_PROC_RSTATE_WRITE_REGION1    (1ULL << 1)

#define SHADOW_PROC_STATE_RESET        0
#define SHADOW_PROC_STATE_INIT        1
#define SHADOW_PROC_STATE_READY        2
#define SHADOW_PROC_STATE_RUN        3

#define SHADOW_PROC_FLAG_RUN    0

#define SHADOW_PROC_MTU 512

#define SHADOW_PROC_FRAME_SIZE(s) ALIGN(18 + (s), SMP_CACHE_BYTES)

#define SHADOW_PROC_VQ_ALIGN 64

#define SHADOW_PROC_REGION_TX        0
#define SHADOW_PROC_REGION_RX        1

#define SHADOW_PROC_VECTOR_STATE        0
#define SHADOW_PROC_VECTOR_TX_RX        1
#define SHADOW_PROC_VECTOR_OK           2

#define SHADOW_PROC_NUM_VECTORS        2

#define SPDRBASE 'k'
#define SPDR_TCB _IOR(SPDRBASE, 1, u64)
#define SPDR_DEL _IOW(SPDRBASE, 2, u64)
#define SPDR_SIG _IOW(SPDRBASE, 8, u64)

struct shadow_proc_regs {
    u32 id;
    u32 doorbell;
    u32 lstate;
    u32 rstate;
    u32 rstate_write_lo;
    u32 rstate_write_hi;
};

struct shadow_proc_queue {
    struct vring vr;
    u32 free_head;
    u32 num_free;
    u32 num_added;
    u16 last_avail_idx;
    u16 last_used_idx;

    void *data;
    void *end;
    u32 size;
    u32 head;
    u32 tail;
};

struct shadow_proc_info {
    struct cdev cdev;
    struct pci_dev *dev;
    struct shadow_proc_regs __iomem *regs;
    resource_size_t shmaddr[2];
    resource_size_t shmlen; // min
    void* shm[2];

    struct shadow_proc_queue rx;
    struct shadow_proc_queue tx;

    u32 vrsize;
    u32 qlen;
    u32 qsize;

    spinlock_t tx_free_lock;
    spinlock_t tx_clean_lock;

    u32 lstate;
    u32 *rstate, last_rstate;

    unsigned long flags;

    struct workqueue_struct *state_wq;
    struct work_struct state_work;
    struct workqueue_struct *recv_wq;
    struct work_struct recv_work;
};

static int    majorNumber = 0;
static struct class*  dev_class  = NULL;
static struct device* dev_device = NULL;

struct process_item{
    u64 nbr;
    u64 arguments[6];
    u64 nuttx_tcb;
    u64 nuttx_prio;

    u64 linux_tcb;
    wait_queue_head_t lock;
    u64 has_msg;
    struct shadow_proc_info* in;
};
// {nbr, 1~6, recved nuttx tcb addr, linux tcb addr}

static u64 process_list_init;
static struct process_item process_list[128];

/***************************************
 * Queue Helpers
 ***************************************/

static int shadow_proc_calc_qsize(struct shadow_proc_info* priv)
{
    unsigned int vrsize;
    unsigned int qsize;
    unsigned int qlen;

    for (qlen = 4096; qlen > 32; qlen >>= 1) {
        vrsize = vring_size(qlen, SHADOW_PROC_VQ_ALIGN);
        vrsize = ALIGN(vrsize, SHADOW_PROC_VQ_ALIGN);
        if (vrsize < (priv->shmlen - 4) / 8)
            break;
    }

    if (vrsize > priv->shmlen - 4)
        return -EINVAL;

    qsize = priv->shmlen - 4 - vrsize;

    if (qsize < 4 * SHADOW_PROC_MTU)
        return -EINVAL;

    priv->vrsize = vrsize;
    priv->qlen = qlen;
    priv->qsize = qsize;

    return 0;
}

static void shadow_proc_init_queue(struct shadow_proc_info *in,
                 struct shadow_proc_queue *q,
                 void *mem, unsigned int len)
{
    memset(q, 0, sizeof(*q));

    vring_init(&q->vr, len, mem, SHADOW_PROC_VQ_ALIGN);
    q->data = mem + in->vrsize;
    q->end = q->data + in->qsize;
    q->size = in->qsize;
}

static void shadow_proc_init_queues(struct shadow_proc_info *in)
{
    int i;
    void *tx = in->shm[SHADOW_PROC_REGION_TX] + 4;
    void *rx = in->shm[SHADOW_PROC_REGION_RX] + 4;

    memset(tx, 0, in->shmlen - 4);

    shadow_proc_init_queue(in, &in->tx, tx, in->qlen);
    shadow_proc_init_queue(in, &in->rx, rx, in->qlen);

    swap(in->rx.vr.used, in->tx.vr.used);

    in->tx.num_free = in->tx.vr.num;

    for (i = 0; i < in->tx.vr.num - 1; i++)
        in->tx.vr.desc[i].next = i + 1;
}

/***************************************
 * IRQ Helpers
 ***************************************/

static void shadow_proc_notify_tx(struct shadow_proc_info *in, unsigned int num, u64 prio)
{
    u16 evt, old, new;
    u64 remote_prio;

    virt_mb();

    evt = READ_ONCE(vring_avail_event(&in->tx.vr));
    old = in->tx.last_avail_idx - num;
    new = in->tx.last_avail_idx;
    remote_prio = *(volatile uint64_t*)(in->shm[SHADOW_PROC_REGION_RX] + in->shmlen);

        /* only send IPI if necessary */
    if(remote_prio <= prio){
        /*if (vring_need_event(evt, new, old))*/
            writel(SHADOW_PROC_VECTOR_TX_RX, &in->regs->doorbell);
    /*}else{*/
    }
}

static void shadow_proc_enable_rx_irq(struct shadow_proc_info *in)
{
    vring_avail_event(&in->rx.vr) = in->rx.last_avail_idx;
    virt_wmb();
}

/***************************************
 * Request processor
 ***************************************/

static void *shadow_proc_desc_data(struct shadow_proc_info *in,
                 struct shadow_proc_queue *q,
                 unsigned int region,
                 struct vring_desc *desc,
                 u32 *len)
{
    u64 offs = READ_ONCE(desc->addr);
    u32 dlen = READ_ONCE(desc->len);
    u16 flags = READ_ONCE(desc->flags);
    void *data;

    if (flags)
        return NULL;

    if (offs >= in->shmlen)
        return NULL;

    data = in->shm[region] + offs;

    if (data < q->data || data >= q->end)
        return NULL;

    if (dlen > q->end - data)
        return NULL;

    *len = dlen;

    return data;
}

static struct vring_desc *shadow_proc_rx_desc(struct shadow_proc_info *in)
{
    struct shadow_proc_queue *rx = &in->rx;
    struct vring *vr = &rx->vr;
    unsigned int avail;
    u16 avail_idx;

    avail_idx = virt_load_acquire(&vr->avail->idx);

    if (avail_idx == rx->last_avail_idx)
        return NULL;

    avail = vr->avail->ring[rx->last_avail_idx++ & (vr->num - 1)];
    if (avail >= vr->num) {
        printk("invalid rx avail %d\n", avail);
        return NULL;
    }

    return &vr->desc[avail];
}

static void shadow_proc_rx_finish(struct shadow_proc_info *in, struct vring_desc *desc)
{
    struct shadow_proc_queue *rx = &in->rx;
    struct vring *vr = &rx->vr;
    unsigned int desc_id = desc - vr->desc;
    unsigned int used;

    used = rx->last_used_idx++ & (vr->num - 1);
    vr->used->ring[used].id = desc_id;
    vr->used->ring[used].len = 1;

    virt_store_release(&vr->used->idx, rx->last_used_idx);
}

static u32 shadow_proc_tx_advance(struct shadow_proc_queue *q, u32 *pos, u32 len)
{
    u32 p = *pos;

    len = SHADOW_PROC_FRAME_SIZE(len);

    if (q->size - p < len)
        p = 0;
    *pos = p + len;

    return p;
}

static void shadow_proc_tx_clean(struct shadow_proc_info *in)
{
    struct shadow_proc_queue *tx = &in->tx;
    struct vring_used_elem *used;
    struct vring *vr = &tx->vr;
    struct vring_desc *desc;
    struct vring_desc *fdesc;
    unsigned int num;
    u16 used_idx;
    u16 last;
    u32 fhead;

    if (!spin_trylock(&in->tx_clean_lock))
        return;

    used_idx = virt_load_acquire(&vr->used->idx);
    last = tx->last_used_idx;

    fdesc = NULL;
    fhead = 0;
    num = 0;

    while (last != used_idx) {
        void *data;
        u32 len;
        u32 tail;

        used = vr->used->ring + (last % vr->num);
        if (used->id >= vr->num || used->len != 1) {
            printk("invalid tx used->id %d ->len %d\n",
                   used->id, used->len);
            break;
        }

        desc = &vr->desc[used->id];

        data = shadow_proc_desc_data(in, &in->tx, SHADOW_PROC_REGION_TX,
                       desc, &len);
        if (!data) {
            printk("bad tx descriptor, data == NULL\n");
            break;
        }

        tail = shadow_proc_tx_advance(tx, &tx->tail, len);
        if (data != tx->data + tail) {
            printk("bad tx descriptor %p %p %llx\n", data, tx->data, tail);
            break;
        }

        if (!num)
            fdesc = desc;
        else
            desc->next = fhead;

        fhead = used->id;
        last++;
        num++;
    }

    tx->last_used_idx = last;

    spin_unlock(&in->tx_clean_lock);

    if (num) {
        spin_lock(&in->tx_free_lock);
        fdesc->next = tx->free_head;
        tx->free_head = fhead;
        tx->num_free += num;
        BUG_ON(tx->num_free > vr->num);
        spin_unlock(&in->tx_free_lock);
    }
}


static void shadow_proc_set_state(struct shadow_proc_info *in, u32 state);
static void shadow_proc_run(struct shadow_proc_info *in)
{
    if (in->lstate < SHADOW_PROC_STATE_READY)
        return;

    if (test_and_set_bit(SHADOW_PROC_FLAG_RUN, &in->flags))
        return;

    shadow_proc_set_state(in, SHADOW_PROC_STATE_RUN);
    shadow_proc_enable_rx_irq(in);
}

static void shadow_proc_do_stop(struct shadow_proc_info *in)
{
    shadow_proc_set_state(in, SHADOW_PROC_STATE_RESET);

    if (!test_and_clear_bit(SHADOW_PROC_FLAG_RUN, &in->flags))
        return;
}

static void shadow_proc_transmit(struct shadow_proc_info* in, uint64_t* data, uint64_t prio){
    struct shadow_proc_queue *tx = &in->tx;
    struct vring *vr = &tx->vr;
    struct vring_desc *desc;
    unsigned int desc_idx;
    unsigned int avail;
    u32 head;
    void* buf;

    shadow_proc_tx_clean(in);

    BUG_ON(tx->num_free < 1);

    spin_lock(&in->tx_free_lock);
    desc_idx = tx->free_head;
    desc = &vr->desc[desc_idx];
    tx->free_head = desc->next;
    tx->num_free--;
    spin_unlock(&in->tx_free_lock);

    head = shadow_proc_tx_advance(tx, &tx->head, 24);

    buf = tx->data + head;
    *(u64*)buf = *data;
    *((u64*)buf + 1) = *(data + 1);

    desc->addr = buf - in->shm[SHADOW_PROC_REGION_TX];
    desc->len = sizeof(u64) * 2;
    desc->flags = 0;

    avail = tx->last_avail_idx++ & (vr->num - 1);
    vr->avail->ring[avail] = desc_idx;
    tx->num_added++;

    virt_store_release(&vr->avail->idx, tx->last_avail_idx);

    shadow_proc_notify_tx(in, tx->num_added, prio);

    tx->num_added = 0;
}

static void shadow_proc_receive(struct shadow_proc_info* in, uint64_t* data)
{
    struct vring_desc *desc;
    u64 *buf;
    int len;

    desc = shadow_proc_rx_desc(in);
    if (!desc)
        return;

    buf = (u64*)shadow_proc_desc_data(in, &in->rx, SHADOW_PROC_REGION_RX,
                   desc, &len);
    if (!buf) {
        printk("bad rx descriptor\n");
        return;
    }

    memcpy(data, buf, sizeof(u64) * 10);

    shadow_proc_rx_finish(in, desc);
}

/***************************************
 * Connection State machine
 ***************************************/

static void shadow_proc_set_state(struct shadow_proc_info *in, u32 state)
{
    virt_wmb();
    WRITE_ONCE(in->lstate, state);
    writel(state, &in->regs->lstate);
}

static void shadow_proc_check_state(struct shadow_proc_info *in)
{
    if (*in->rstate != in->last_rstate ||
        !test_bit(SHADOW_PROC_FLAG_RUN, &in->flags))
        queue_work(in->state_wq, &in->state_work);
}

static void shadow_proc_state_change(struct work_struct *work)
{
    struct shadow_proc_info *in = container_of(work, struct shadow_proc_info, state_work);
    u32 rstate = READ_ONCE(*in->rstate);

    switch (in->lstate) {
    case SHADOW_PROC_STATE_RESET:
        if (rstate < SHADOW_PROC_STATE_READY)
            shadow_proc_set_state(in, SHADOW_PROC_STATE_INIT);
        break;

    case SHADOW_PROC_STATE_INIT:
        if (rstate > SHADOW_PROC_STATE_RESET) {
            shadow_proc_init_queues(in);
            shadow_proc_set_state(in, SHADOW_PROC_STATE_READY);
        }
        break;

    case SHADOW_PROC_STATE_READY:
    case SHADOW_PROC_STATE_RUN:
        if (rstate >= SHADOW_PROC_STATE_READY) {
            shadow_proc_run(in);
        } else {
            shadow_proc_do_stop(in);
        }
        break;
    }

    virt_wmb();
    WRITE_ONCE(in->last_rstate, rstate);
}

/***************************************
 * Recv processing
 ***************************************/

static void shadow_proc_recv_handler(struct work_struct *work)
{
    struct shadow_proc_info *in = container_of(work, struct shadow_proc_info, recv_work);
    u64 buf[10];

    // received data {nbr, arguments 1~6, nuttx tcb addr, process_list idx}
    shadow_proc_receive(in, buf);

    if(process_list[buf[9]].linux_tcb){
        memcpy(&process_list[buf[9]], buf, sizeof(u64) * 9);
        process_list[buf[9]].has_msg = 1;
        wake_up_interruptible_sync(&process_list[buf[9]].lock);
        /*up(&process_list[buf[9]].lock);*/
    }else{
        printk("FATAL: SYSCALL without target to wakeup\n");
    }
}

/***************************************
 * IRQ handler
 ***************************************/

static irqreturn_t shadow_proc_int_state(int irq, void *data)
{
    struct shadow_proc_info *in = data;

    shadow_proc_check_state(in);

    return IRQ_HANDLED;
}

static irqreturn_t shadow_proc_int_tx_rx(int irq, void *data)
{
    struct shadow_proc_info *in = data;

    /*queue_work(in->recv_wq, &in->recv_work);*/
    shadow_proc_recv_handler(&in->recv_work);

    return IRQ_HANDLED;
}

static irqreturn_t shadow_proc_int_ok(int irq, void *data)
{
    struct shadow_proc_info *in = data;

    return IRQ_HANDLED;
}

/***************************************
 * fops
 ***************************************/

int shadow_proc_open(struct inode *inodep, struct file *filep)
{
    struct shadow_proc_info *in;
    int i;

    in = container_of(inodep->i_cdev, struct shadow_proc_info, cdev);

    for(i = 0; i < 128; i++){
        if(process_list[i].linux_tcb == (uint64_t)current){
            return -EINVAL;
        }
    }

    for(i = 0; i < 128; i++){
        if(process_list[i].linux_tcb == 0){
            memset(&process_list[i], 0, sizeof(process_list[i]));
            process_list[i].linux_tcb = (uint64_t)current;
            init_waitqueue_head (&process_list[i].lock);
            /*sema_init(&process_list[i].lock, 0);*/
            process_list[i].in = in;
            process_list[i].has_msg = 0;
            printk("Process: %llx got slot: %lld\n", process_list[i].linux_tcb, i);
            break;
        }
    }

    filep->private_data = process_list + i;
    return 0;
}

int shadow_proc_release(struct inode *inodep, struct file *filep)
{
    struct process_item* item = filep->private_data;

    item->linux_tcb = 0;

    return 0;
}

long shadow_proc_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
    u64 i;
    struct process_item* this_entry = (struct process_item*) filep->private_data;
    struct shadow_proc_info *in = this_entry->in;
    u64 buf[2];

    if(_IOC_TYPE(cmd) != SPDRBASE) return -EINVAL;

    switch(cmd) {
        case SPDR_TCB:
            i = ((struct process_item*) filep->private_data - process_list);
            copy_to_user((uint64_t*)arg, (uint64_t*)&i, sizeof(u64));
            return 0;
        case SPDR_SIG:
            buf[0] = arg; // The arg is the signal number
            buf[1] = (1ULL << 63) | current->pid;
            shadow_proc_transmit(in, buf, this_entry->nuttx_prio);
            return 0;
        default:
            printk("%p", in);
            return -EINVAL;
    }
}


ssize_t shadow_proc_read(struct file *filep, char __user *addr, size_t len, loff_t *off)
{
    struct process_item* this_entry = (struct process_item*) filep->private_data;
    struct shadow_proc_info *in = this_entry->in;
    int ret;

    ret = wait_event_interruptible(this_entry->lock, this_entry->has_msg);
    if(ret < 0) {
        if(fatal_signal_pending(current)) {
            // Must be SIGKILL or SIGSTOP
           printk("Oh oh, %llx was killed!\n", current);
        }
       return -EINTR;
    }

    copy_to_user(addr, this_entry, sizeof(u64) * 9);

    this_entry->has_msg = 0;

    return 8;
}


ssize_t shadow_proc_write(struct file *filep, const char __user *addr, size_t len, loff_t *off)
{
    struct process_item* this_entry = (struct process_item*) filep->private_data;
    struct shadow_proc_info *in = this_entry->in;
    u64 buf[2];

    copy_from_user(buf, addr, sizeof(u64));

    buf[1] = this_entry->nuttx_tcb;

    shadow_proc_transmit(in, buf, this_entry->nuttx_prio);

    return len;
}

unsigned int shadow_proc_poll(struct file *filep, poll_table *wait)
{
    struct process_item* this_entry = (struct process_item*) filep->private_data;
    struct shadow_proc_info *in = this_entry->in;
    unsigned int mask = POLLOUT;

    if(this_entry->has_msg) mask |= POLLIN;

    poll_wait(filep, &this_entry->lock, wait);

    return mask;
}

/***************************************
 * Probe and Remove
 ***************************************/

static struct file_operations fops =
{
   .open = shadow_proc_open,
   .release = shadow_proc_release,
   .unlocked_ioctl = shadow_proc_ioctl,
   .read = shadow_proc_read,
   .write = shadow_proc_write,
   .poll = shadow_proc_poll,
};

static int shadow_proc_pci_probe(struct pci_dev *pdev,
                    const struct pci_device_id *pci_id)
{
    struct shadow_proc_info *shadow_proc_info;

    unsigned int region, cap_pos;
    char *device_name;
    int vendor_cap;
    u32 id, dword;
    u64 qword;
    int ret;

    if(!process_list_init){
        memset(process_list, 0, sizeof(process_list));
        process_list_init = 1;
    }

    shadow_proc_info = kzalloc(sizeof(struct shadow_proc_info), GFP_KERNEL);
    if (!shadow_proc_info) {
        kfree(shadow_proc_info);
        return -ENOMEM;
    }

    ret = pcim_enable_device(pdev);
    if (ret) {
        dev_err(&pdev->dev, "pci_enable_device: %d\n", ret);
        return ret;
    }

    device_name = devm_kasprintf(&pdev->dev, GFP_KERNEL, "%s[%s]", DRV_NAME,
                     dev_name(&pdev->dev));
    if (!device_name)
        return -ENOMEM;

    ret = pcim_iomap_regions(pdev, BIT(0), DRV_NAME);
    if (ret) {
        dev_err(&pdev->dev, "pcim_iomap_regions: %d\n", ret);
        return ret;
    }

    shadow_proc_info->regs = pcim_iomap_table(pdev)[0];

    vendor_cap = pci_find_capability(pdev, PCI_CAP_ID_VNDR);
    if (vendor_cap < 0) {
        dev_err(&pdev->dev, "missing vendor capability\n");
        return -EINVAL;
    }

    shadow_proc_info->shmlen = 0xffffffff;
    for (region = 0; region < 2; region++) {
        cap_pos = vendor_cap + JAILHOUSE_CFG_SHMEM_ADDR1 + region * 16;
        pci_read_config_dword(pdev, cap_pos, &dword);
        shadow_proc_info->shmaddr[region] = dword;
        pci_read_config_dword(pdev, cap_pos + 4, &dword);
        shadow_proc_info->shmaddr[region] |= (u64)dword << 32;

        cap_pos = vendor_cap + JAILHOUSE_CFG_SHMEM_SIZE1 + region * 16;
        pci_read_config_dword(pdev, cap_pos + 4, &dword);
        qword = (u64)dword << 32;
        pci_read_config_dword(pdev, cap_pos, &dword);
        qword |= dword;
        if(qword < shadow_proc_info->shmlen)
            shadow_proc_info->shmlen = qword;

        if (!devm_request_mem_region(&pdev->dev, shadow_proc_info->shmaddr[region],
                         qword, DRV_NAME))
            return -EBUSY;

        shadow_proc_info->shm[region] =
            devm_memremap(&pdev->dev,
                    shadow_proc_info->shmaddr[region],
                    qword,
                    MEMREMAP_WB);
        if (!shadow_proc_info->shm[region])
            return -ENOMEM;

        dev_info(&pdev->dev, "%s memory at %pa, size %pa\n",
             region == SHADOW_PROC_REGION_TX ? "TX" : "RX",
             &shadow_proc_info->shmaddr[region], &qword);
    }

    shadow_proc_info->shmlen -= PAGE_SIZE;

    shadow_proc_info->dev = pdev;
    pci_set_drvdata(pdev, shadow_proc_info);
    spin_lock_init(&shadow_proc_info->tx_free_lock);
    spin_lock_init(&shadow_proc_info->tx_clean_lock);

    ret = shadow_proc_calc_qsize(shadow_proc_info);
    if (ret)
        goto err_free;

    shadow_proc_info->state_wq = alloc_ordered_workqueue(device_name, 0);
    shadow_proc_info->recv_wq = create_singlethread_workqueue("shadow-recv");
    if (!shadow_proc_info->state_wq)
        goto err_free;
    if (!shadow_proc_info->recv_wq)
        goto err_free;

    INIT_WORK(&shadow_proc_info->state_work, shadow_proc_state_change);
    INIT_WORK(&shadow_proc_info->recv_work, shadow_proc_recv_handler);

    ret = pci_alloc_irq_vectors(pdev, 1, 3, PCI_IRQ_LEGACY | PCI_IRQ_MSIX);
    if (ret < 0){
        printk("NO IRQ\n");
        goto err_wq;
    }

    if (!pdev->msix_enabled) {
        ret = -EBUSY;
        printk("NO MSIX\n");
        goto err_wq;
    }

    printk("MSIX\n");
    if (ret != 3) {
        dev_info(&pdev->dev, "Too Few IRQ %d\n", ret);
        ret = -EBUSY;
        goto err_wq;
    }

    device_name = devm_kasprintf(&pdev->dev, GFP_KERNEL,
                     "%s-state[%s]", DRV_NAME,
                     dev_name(&pdev->dev));
    if (!device_name) {
        ret = -ENOMEM;
        goto err_wq;
    }

    ret = request_any_context_irq(pci_irq_vector(pdev, SHADOW_PROC_VECTOR_STATE),
              shadow_proc_int_state, 0, device_name, shadow_proc_info);
    if (ret)
        goto err_request_irq;

    device_name = devm_kasprintf(&pdev->dev, GFP_KERNEL,
                     "%s-tx-rx[%s]", DRV_NAME,
                     dev_name(&pdev->dev));
    if (!device_name) {
        ret = -ENOMEM;
        goto err_request_irq2;
    }

    ret = request_any_context_irq(pci_irq_vector(pdev, SHADOW_PROC_VECTOR_TX_RX),
              shadow_proc_int_tx_rx, 0, device_name, shadow_proc_info);
    if (ret)
        goto err_request_irq2;

    ret = request_any_context_irq(pci_irq_vector(pdev, SHADOW_PROC_VECTOR_OK),
              shadow_proc_int_ok, 0, device_name, shadow_proc_info);
    if (ret)
        goto err_request_irq3;

    pci_set_master(pdev);

    shadow_proc_info->rstate = shadow_proc_info->shm[SHADOW_PROC_REGION_TX];

    /* First make sure that rstate writing is disabled. */
    writel(0, &shadow_proc_info->regs->rstate_write_lo);

    writel(0x0, &shadow_proc_info->regs->rstate_write_hi);
    writel(0x0 | SHADOW_PROC_RSTATE_WRITE_REGION1 | SHADOW_PROC_RSTATE_WRITE_ENABLE,
           &shadow_proc_info->regs->rstate_write_lo);

    writel(SHADOW_PROC_STATE_RESET, &shadow_proc_info->regs->lstate);
    shadow_proc_check_state(shadow_proc_info);

    dev_device = device_create(dev_class, NULL, MKDEV(majorNumber, 0), pdev, DRV_NAME);
    if (IS_ERR(dev_device)){
        printk(KERN_ALERT "Failed to create device\n");
        goto err_request_irq4;
    }

    printk("Adding cdev: %d\n", majorNumber);
    cdev_init(&shadow_proc_info->cdev, &fops);
    shadow_proc_info->cdev.owner = THIS_MODULE;
    ret = cdev_add(&shadow_proc_info->cdev, MKDEV(majorNumber, 0), 1);
    if (ret < 0) {
        printk(KERN_ALERT "Shadow Process failed to add a character device\n");
        goto err_device;
    }

    *(volatile uint64_t*)(shadow_proc_info->shm[SHADOW_PROC_REGION_TX] + shadow_proc_info->shmlen) = 0;

    virt_wmb();


    return 0;

err_device:
    device_destroy(dev_class, MKDEV(majorNumber, 0));
err_request_irq4:
    free_irq(pci_irq_vector(pdev, SHADOW_PROC_VECTOR_OK), shadow_proc_info);
err_request_irq3:
    free_irq(pci_irq_vector(pdev, SHADOW_PROC_VECTOR_TX_RX), shadow_proc_info);
err_request_irq2:
    free_irq(pci_irq_vector(pdev, SHADOW_PROC_VECTOR_STATE), shadow_proc_info);
err_request_irq:
    pci_free_irq_vectors(pdev);
err_wq:
    destroy_workqueue(shadow_proc_info->state_wq);
err_free:
    kfree(shadow_proc_info);

    return ret;
}

static void shadow_proc_pci_remove(struct pci_dev *pdev)
{
    struct shadow_proc_info* in = pci_get_drvdata(pdev);

    writel(SHADOW_PROC_STATE_RESET, &in->regs->lstate);

    free_irq(pci_irq_vector(pdev, SHADOW_PROC_VECTOR_STATE), in);
    free_irq(pci_irq_vector(pdev, SHADOW_PROC_VECTOR_TX_RX), in);
    free_irq(pci_irq_vector(pdev, SHADOW_PROC_VECTOR_OK), in);
    pci_free_irq_vectors(pdev);

    cancel_work_sync(&in->state_work);
    destroy_workqueue(in->state_wq);
    cancel_work_sync(&in->recv_work);
    destroy_workqueue(in->recv_wq);

    cdev_del(&in->cdev);             // unregister the major number
}

static struct pci_device_id shadow_proc_pci_ids[] = {
    { PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, 0x1110),
        (PCI_CLASS_OTHERS << 16) | (0xffff), 0xffff00 },
    { 0 }
};

static struct pci_driver shadow_proc_pci_driver = {
    .name = DRV_NAME,
    .id_table = shadow_proc_pci_ids,
    .probe = shadow_proc_pci_probe,
    .remove = shadow_proc_pci_remove,
};

/* For capturing SIGKILL and SIGSTOP */
static struct kprobe kp = {
    .symbol_name    = "send_signal",
};

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    int sig = regs->di;
    struct task_struct* t = regs->dx;

    int i;

    for(i = 0; i < 128; i++) {
        if(process_list[i].linux_tcb == t) {
            /* these 2 are tricky, we handle them here */
            if(sig == SIGKILL || sig == SIGSTOP) {
                printk("%llx signaled %llx with %d\n", current, t, sig);

                u64 buf[4];

                buf[0] = sig;
                buf[1] = 0;
                buf[2] = (1ULL << 63) | t->pid;

                shadow_proc_transmit(process_list[i].in, buf, process_list[i].nuttx_prio);
            }
        }
    }

    return 0;
}

static void handler_post(struct kprobe *p, struct pt_regs *regs,
                unsigned long flags)
{
    return;
}

static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    return 0;
}

//Drivers entry function. register with the pci core and the serial core
static int __init shadow_proc_init(void)
{
    int ret;

    kp.pre_handler = handler_pre;
    kp.post_handler = handler_post;
    kp.fault_handler = handler_fault;

    /*ret = register_kprobe(&kp);*/
    ret = 0;
    if (ret < 0) {
        printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "Planted kprobe at %p\n", kp.addr);

    dev_t devno = MKDEV(0, 0);
    ret = alloc_chrdev_region(&devno, 0, 1, DRV_NAME);
    if(ret < 0){
        printk(KERN_ERR "Shadow Process failed to register a major number\n");
        goto err_alloc;
    }
    majorNumber = MAJOR(devno);

    dev_class = class_create(THIS_MODULE, DRV_NAME);
    if (IS_ERR(dev_class)){
        printk(KERN_ERR "Failed to register device class\n");
        goto err_major;
    }

    ret = pci_register_driver(&shadow_proc_pci_driver);
    if (ret < 0){
        printk(KERN_ERR "In %s pci_register_driver FAILED\n", __FUNCTION__);
        goto err_class;
    }

    return 0;

err_class:
    class_unregister(dev_class);
    class_destroy(dev_class);
err_major:
    unregister_chrdev_region(MKDEV(majorNumber, 0), 1);
err_alloc:
    unregister_kprobe(&kp);
    return ret;
}

//Drivers exit function. Unregister with the PCI core as well as serial core
static void __exit shadow_proc_exit(void)
{
    device_destroy(dev_class, MKDEV(majorNumber, 0));
    class_unregister(dev_class);
    class_destroy(dev_class);
    unregister_chrdev_region(MKDEV(majorNumber, 0), 1);
    pci_unregister_driver(&shadow_proc_pci_driver);
    unregister_kprobe(&kp);
}

module_init(shadow_proc_init);
module_exit(shadow_proc_exit);

MODULE_DEVICE_TABLE(pci, shadow_proc_pci_ids);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Yang ChungFan");
