/*
 * UIO IVShmem Driver
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
#include <linux/uio_driver.h>
#include <linux/io.h>

#define IntrStatus 0x04
#define IntrMask 0x00

#define IVSHMEM_CFG_VENDOR_CAP 0x40
#define IVSHMEM_CFG_VENDOR_LEN 20
#define IVSHMEM_CFG_MSIX_CAP   (IVSHMEM_CFG_VENDOR_CAP+IVSHMEM_CFG_VENDOR_LEN)
#define IVSHMEM_CFG_SHMEM_ADDR (IVSHMEM_CFG_VENDOR_CAP + 4)
#define IVSHMEM_CFG_SHMEM_SIZE (IVSHMEM_CFG_VENDOR_CAP + 12)

struct ivshmem_info {
	struct uio_info *uio;
	struct pci_dev *dev;
	int jailhouse_mode;
};

static irqreturn_t ivshmem_handler(int irq, struct uio_info *dev_info)
{

	struct ivshmem_info *ivshmem_info;
	void __iomem *plx_intscr;
	u32 val;

	ivshmem_info = dev_info->priv;

	if (ivshmem_info->dev->msix_enabled)
		return IRQ_HANDLED;

	/* jailhouse does not implement IntrStatus */
	if (ivshmem_info->jailhouse_mode)
		return IRQ_HANDLED;

	plx_intscr = dev_info->mem[0].internal_addr + IntrStatus;
	val = readl(plx_intscr);
	if (val == 0)
		return IRQ_NONE;

	return IRQ_HANDLED;
}

static const struct vm_operations_struct uio_physical_vm_ops = {
#ifdef CONFIG_HAVE_IOREMAP_PROT
	.access = generic_access_phys,
#endif
};

static int uio_mmap_physical(int mi, struct vm_area_struct *vma)
{
	struct uio_device *idev = vma->vm_private_data;
	struct uio_mem *mem;
	if (mi < 0)
		return -EINVAL;
	mem = idev->info->mem + mi;

	if (mem->addr & ~PAGE_MASK)
		return -ENODEV;
	if (vma->vm_end - vma->vm_start > mem->size)
		return -EINVAL;

	vma->vm_ops = &uio_physical_vm_ops;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

    if(mi == 0) {
        /*
         * We cannot use the vm_iomap_memory() helper here,
         * because vma->vm_pgoff is the map index we looked
         * up above in uio_find_mem_index(), rather than an
         * actual page offset into the mmap.
         *
         * So we just do the physical mmap without a page
         * offset.
         */
        return remap_pfn_range(vma,
                       vma->vm_start,
                       mem->addr >> PAGE_SHIFT,
                       vma->vm_end - vma->vm_start,
                       vma->vm_page_prot);
    } else {
        /* although helper could be used, didn't brother */
        return remap_pfn_range(vma,
                       vma->vm_start,
                       (mem->addr >> PAGE_SHIFT) + vma->vm_pgoff - 1,
                       vma->vm_end - vma->vm_start,
                       vma->vm_page_prot);

    }

}

static int ivshmem_mmap(struct uio_info *info, struct vm_area_struct *vma)
{
	struct uio_device *idev = info->uio_dev;
	int mi;
	unsigned long requested_pages, actual_pages;

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;

	vma->vm_private_data = idev;

    requested_pages = vma_pages(vma);

    mi = (int)vma->vm_pgoff;
    if (mi < 0)
        return -EINVAL;
    if (mi > 0)
        mi = 1;

    if (mi == 0){
        actual_pages = ((idev->info->mem[mi].addr & ~PAGE_MASK)
                + idev->info->mem[mi].size + PAGE_SIZE -1) >> PAGE_SHIFT;
        if (requested_pages > actual_pages)
            return -EINVAL;
    }
    return uio_mmap_physical(mi, vma);
}

static int ivshmem_pci_probe(struct pci_dev *dev,
					const struct pci_device_id *id)
{
	struct uio_info *info;
	struct ivshmem_info *ivshmem_info;

	info = kzalloc(sizeof(struct uio_info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

    info->mmap = ivshmem_mmap;

	ivshmem_info = kzalloc(sizeof(struct ivshmem_info), GFP_KERNEL);
	if (!ivshmem_info) {
		kfree(info);
		return -ENOMEM;
	}
	info->priv = ivshmem_info;

	if (pci_enable_device(dev))
		goto out_free;

	if (pci_request_regions(dev, "ivshmem"))
		goto out_disable;

	info->mem[0].addr = pci_resource_start(dev, 0);
	if (!info->mem[0].addr)
		goto out_release;

	info->mem[0].size = (pci_resource_len(dev, 0) + PAGE_SIZE - 1)
		& PAGE_MASK;
	info->mem[0].internal_addr = pci_ioremap_bar(dev, 0);
	if (!info->mem[0].internal_addr)
		goto out_release;

	if (1 > pci_alloc_irq_vectors(dev, 1, 1,
				      PCI_IRQ_LEGACY | PCI_IRQ_MSIX))
		goto out_vector;

	info->mem[0].memtype = UIO_MEM_PHYS;
	info->mem[0].name = "registers";

    pci_read_config_dword(dev, IVSHMEM_CFG_SHMEM_ADDR,
        (u32*)&info->mem[1].addr);
    pci_read_config_dword(dev, IVSHMEM_CFG_SHMEM_ADDR + 4,
        ((u32*)&info->mem[1].addr) + 1);
    pci_read_config_dword(dev, IVSHMEM_CFG_SHMEM_SIZE,
        (u32*)&info->mem[1].size);
    pci_read_config_dword(dev, IVSHMEM_CFG_SHMEM_SIZE + 4,
        ((u32*)&info->mem[1].size) + 1);
	if (!info->mem[1].addr)
		goto out_unmap;

    dev_info(&dev->dev, "using jailhouse mode\n");
    ivshmem_info->jailhouse_mode = 1;

	info->mem[1].memtype = UIO_MEM_PHYS;
	info->mem[1].name = "shmem";

	ivshmem_info->uio = info;
	ivshmem_info->dev = dev;

	if (pci_irq_vector(dev, 0)) {
		info->irq = pci_irq_vector(dev, 0);
		info->irq_flags = IRQF_SHARED;
		info->handler = ivshmem_handler;
	} else {
		dev_warn(&dev->dev, "No IRQ assigned to device: "
			 "no support for interrupts?\n");
	}
	pci_set_master(dev);

	info->name = "uio_ivshmem";
	info->version = "0.0.1";

	if (uio_register_device(&dev->dev, info))
		goto out_unmap;

	if (!dev->msix_enabled)
		writel(0xffffffff, info->mem[0].internal_addr + IntrMask);

	pci_set_drvdata(dev, ivshmem_info);

	return 0;
out_vector:
	pci_free_irq_vectors(dev);
out_unmap:
	iounmap(info->mem[0].internal_addr);
out_release:
	pci_release_regions(dev);
out_disable:
	pci_disable_device(dev);
out_free:
	kfree(ivshmem_info);
	kfree(info);
	return -ENODEV;
}

static void ivshmem_pci_remove(struct pci_dev *dev)
{
	struct ivshmem_info *ivshmem_info = pci_get_drvdata(dev);
	struct uio_info *info = ivshmem_info->uio;

	pci_set_drvdata(dev, NULL);
	uio_unregister_device(info);
	pci_free_irq_vectors(dev);
	iounmap(info->mem[0].internal_addr);
	pci_release_regions(dev);
	pci_disable_device(dev);
	kfree(info);
	kfree(ivshmem_info);
}

static struct pci_device_id ivshmem_pci_ids[] = {
	{
		.vendor =	0x1af4,
		.device =	0x1110,
		.subvendor =	PCI_ANY_ID,
		.subdevice =	PCI_ANY_ID,
	},
	{ 0, }
};

static struct pci_driver ivshmem_pci_driver = {
	.name = "uio_ivshmem",
	.id_table = ivshmem_pci_ids,
	.probe = ivshmem_pci_probe,
	.remove = ivshmem_pci_remove,
};

module_pci_driver(ivshmem_pci_driver);
MODULE_DEVICE_TABLE(pci, ivshmem_pci_ids);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Cam Macdonell");
