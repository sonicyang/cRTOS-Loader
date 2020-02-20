#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <cmath>
#include <cassert>
#include <iostream>
#include <vector>
#include <stdexcept>
#include <thread>

#include <unistd.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>

#include <LIEF/LIEF.hpp>
#include <sys/stat.h>

#include "Proxy.hpp"
#include "UIO.hpp"
#include "IO.hpp"
#include "SyscallDecoder.hpp"

#define _VERBOSE(x) do{if(this->verbose) x;}while(0);
#define VERBOSE(x) do{_VERBOSE(std::clog << x << std::endl)}while(0);

extern "C" long raw_syscall(long nbr, long p1, long p2, long p3, long p4, long p5, long p6);

thread_local Proxy* this_proxy;

static std::vector<std::string> getPATHs(){
    std::string PATH = std::getenv("PATH");
    // Search the PATH, this is standard in POSIX
    std::vector<std::string> PATHs;
    PATHs.push_back("");

    std::string delimiter = ":";
    size_t pos = 0;
    std::string token;
    while ((pos = PATH.find(delimiter)) != std::string::npos) {
        token = PATH.substr(0, pos);
        if(token != ""){
            if(token[token.length() - 1] != '/')
                token.push_back('/');
            PATHs.push_back(token);
        }
        PATH.erase(0, pos + delimiter.length());
    }
    return PATHs;
}

static void* dummy_thread(void* arg) {
    struct thread_s* t = (struct thread_s*)arg;
    Proxy* tproxy = t->tproxy;

    tproxy->self_init();

    uint64_t tid = syscall(186);

    tid = ((tid & 0xffffULL) << 48) | (tproxy->get_slot_num() & ~(0xffffULL << 48)); // Encode the tid
    write(t->tpip[1], &tid, sizeof(uint64_t));

    tproxy->run();

    pthread_exit(0);
}

void signal_capture (int signum) {
    this_proxy->send_remote_signal(signum);
    return;
}

void Proxy::init_signal_handling() {
    // This is per-process
    struct sigaction new_action, old_action;

    /* Set up the structure to specify the new action. */
    new_action.sa_handler = signal_capture;
    sigemptyset (&new_action.sa_mask);
    new_action.sa_flags = 0;

    sigaction (SIGHUP,  &new_action, NULL);
    sigaction (SIGINT,  &new_action, NULL);
    sigaction (SIGQUIT, &new_action, NULL);
    sigaction (SIGTERM, &new_action, NULL);
    sigaction (SIGCONT, &new_action, NULL);
}

void Proxy::self_init() {

    this->fd = open(shadow.c_str(), O_RDWR);

    ioctl(this->fd, _IOR('k', 1, uint64_t), &this->slot_num);
    VERBOSE("SLOT:" << this->slot_num);

    this_proxy = this;
}

void Proxy::init_sched() {
    // First check current process sched policy and priority
    struct sched_param param;
    this->policy = sched_getscheduler(0);
    if( policy == -1 ) {
        std::runtime_error("failed to get sched policy");
    }
    if( policy != SCHED_FIFO && policy != SCHED_RR) {
        std::runtime_error("SCHED policy must be SCHED_FIFO or SCHED_RR");
    }
    if( sched_getparam(0, &param) ) {
        std::runtime_error("failed to get sched parameter");
    }

    if(param.sched_priority > 99 || param.sched_priority < 1)
        throw std::out_of_range("priority must between 1 ~ 99");

    this->priority = param.sched_priority;
}

Proxy::Proxy(IO &io, std::string shadow, std::string appmem, bool verbose) :
    io(io),
    shadow(shadow),
    appmem(appmem),
    is_main(false),
    verbose(verbose)
{
    this->stack_memory = NULL;

    return;
}

Proxy::~Proxy() {

    close(this->fd);

    if(this->stack_memory)
        delete this->stack_memory;
    return;
}

void Proxy::rexec(std::string path, std::vector<std::string> argv, std::vector<std::string> envp) {
    /* Then we are the main thread, should be */
    this->is_main = true;

    this->stack_memory = new UIO(this->appmem, (void*)STACKMEM_START, STACKMEM_SIZE, STACKMEM_START - APPMEM_START);

    this->init_signal_handling();

    this->self_init();
    this->init_sched();

    VERBOSE("Rexec entering starting binary");

    // Conduct the path search
    auto PATHs = getPATHs();

    bool exist = false;
    struct stat buffer;
    for ( auto PATH : PATHs ) {
        if(stat ((PATH + path).c_str(), &buffer) == 0){
            path = PATH + path;
            exist = true;
        }
    }

    if(!exist) {
        VERBOSE("No such file or directory: " << path);
        exit(-127);
    }

    uint32_t argc = argv.size();
    uint32_t envc = envp.size();

    std::basic_string<uint8_t> ll_data;
    for( auto item : argv ) {
        uint16_t tmp = item.length();
        ll_data.push_back(((uint8_t*)(&tmp))[0]);
        ll_data.push_back(((uint8_t*)(&tmp))[1]);
        for( int i = 0 ; i < item.length(); i++ ){
            ll_data.push_back(item.c_str()[i]);
        }
        ll_data.push_back('\0');
    }

    for( auto item : envp ) {
        uint16_t tmp = item.length();
        ll_data.push_back(((uint8_t*)(&tmp))[0]);
        ll_data.push_back(((uint8_t*)(&tmp))[1]);
        for( int i = 0 ; i < item.length(); i++ ){
            ll_data.push_back(item.c_str()[i]);
        }
        ll_data.push_back('\0');
    }

    uint64_t tmp[5] = {
        path.length(),
        ((uint64_t)this->policy << 32) | (uint64_t)this->priority,
        ((getpid() & 0xffffULL) << 48) | (this->slot_num & ~(0xffffULL << 48)),
        argc,
        envc
    };
    std::basic_string<uint8_t> data((uint8_t*)&tmp, sizeof(tmp));
    data += std::basic_string<uint8_t>((uint8_t*)(path.c_str()), path.length() + 1);
    data += ll_data;
    this->io.send(REXEC, data);

    this->run();
}

void Proxy::run() {
    SyscallDecoder& scdecode = SyscallDecoder::get_instance();

    struct pollfd pollfds[1];

    int rdbytes;

    bool run = true;
    uint64_t params[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
    //params are also used as return value
    //On recv, {nbr, 1, 2, 3, 4, 5, 6, policy | prio}
    //On transmit, {retval}

    while( run ) {
        rdbytes = read(this->fd, params, sizeof(params));

        // On signal, skip
        if(rdbytes <= 0)
            continue;

        uint64_t nbr = params[0];

        int64_t curr_errno = 0;

        uint64_t policy_prio = params[7];

        if(this->policy != ((policy_prio >> 32) & 0xFFFFFFFF) || this->priority != ((policy_prio) & 0xFFFFFFFF)) {
            this->policy    = ((policy_prio >> 32) & 0xFFFFFFFF);
            this->priority  = ((policy_prio) & 0xFFFFFFFF);

            // The nuttx SCHED_FIFO/SCHED_RR has the same numbering
            struct sched_param param;
            param.sched_priority = this->priority;
            sched_setscheduler(0, this->policy, &param);
        }

        switch(nbr) {
            case 231:
            case 60: // Hook Exit
                run = false;
                params[0] = params[1];
                curr_errno = 0;
                break;
            case 9:
                {
                // Hook mmap
                // Hack the addr parameter, because we are only using 4GB ogf memory
                // We can store 2 address in a 64bit parameter.
                // The upper part is the physical address
                // The lower part is the mapped virtual address
                uintptr_t virtual_addr = params[1] & 0xffffffff;
                uintptr_t physical_addr = (params[1] >> 32) & 0xffffffff;

                // Now we have to provide the same mapping in Both realms


                if((params[4] & MAP_ANONYMOUS)){
                    mappings.push_front(new UIO(this->appmem, (void*)virtual_addr, params[2], physical_addr - APPMEM_START));
                } else {
                    params[4] &= ~MAP_FIXED;
                    void* file_mem = mmap(0, params[2], PROT_READ, params[4], params[5], params[6]);
                    if(file_mem == MAP_FAILED) {
                        params[0] = (uint64_t)MAP_FAILED;
                        perror("MAP FAILED");
                        fprintf(stderr, "%lx %lx %lx %lx %lx %lx", params[1], params[2], params[3], params[4], params[5], params[6]);
                        break;
                    }

                    struct stat st;
                    fstat(params[5], &st);
                    int fsize;
                    fsize = st.st_size;
                    fsize -= params[6]; // Offset are skipped
                    fsize = fsize < params[2] ? fsize : params[2];

                    //for(int i= 0; i < params[2]; i++){
                        //*((volatile uint8_t*)params[1] + i) = 0;
                        //*((volatile uint8_t*)params[1] + i) = *((uint8_t*)file_mem + i);
                    //}
                    memcpy((void*)params[1], file_mem, fsize);

                    munmap(file_mem, params[2]);
                }

                // Return the mapped size
                params[0] = params[2];

                break;
                }
            case 56:
                {
                // Hook clone
                // // We need to create a new thread to get a new pid!

                struct thread_s* t = new struct thread_s;
                t->tproxy = new Proxy(io, shadow, appmem, verbose);
                if (t->tproxy == NULL)
                    throw std::runtime_error("Create a new Proxy!");

                t->tproxy->priority = this->priority;
                t->tproxy->policy = this->policy;

                int ret = pipe(t->tpip);
                if(ret < 0)
                    perror("Pipe failed!");

                threads.push_front(t);

                // This doesn't execute anything but blocks and allocate a tid in Linux kernel
                pthread_create(&t->tid, NULL, dummy_thread, t);

                read(t->tpip[0], &(params[0]), sizeof(uint64_t));

                close(t->tpip[0]);
                close(t->tpip[1]);

                break;
                }

            case 57:
                {
                // Hook fork
                // We need to create a new process to cover the memory space of the new RT process

                int pip[2];
                pipe(pip);

                int pid = fork();

                if(pid){
                    close(pip[1]);
                    read(pip[0], &(params[0]), sizeof(uint64_t));
                    params[0] = ((pid & 0xffffULL) << 48) | (params[0] & ~(0xffffULL << 48)); // Encode the pid
                    close(pip[0]);
                }else{
                    // Register a new slot with kernel
                    this->self_init();

                    //sched is automatically inherited from parent

                    // munmap all mappings
                    for( auto mapping : mappings ) {
                        delete mapping;
                    }
                    mappings.erase(mappings.begin(), mappings.end());

                    // remove information about all threads
                    for( auto thread : threads ) {
                        delete thread;
                    }
                    threads.erase(threads.begin(), threads.end());

                    close(pip[0]);
                    write(pip[1], &this->slot_num, sizeof(uint64_t));
                    close(pip[1]);

                    memset(params, 0, sizeof(params));
                }

                break;
                }
            case 59:
                {
                /* Mimic what should happen after execve */

                //unsigned int maxfd;
                //struct rlimit rlim;
                //getrlimit(RLIMIT_NOFILE, &rlim);
                //maxfd = rlim.rlim_max;
                //for(int i = 3; i < maxfd; i++)
                    //if(i != this->fd)
                        //close(i);

                for( auto mapping : mappings ) {
                    delete mapping;
                }
                mappings.erase(mappings.begin(), mappings.end());

                break;
                }
            case 7: // Poll
                {

                // If the last 3 un-used paramteres are 0xdeadbeef
                // This is a packet for canceling the poll
                if((params[4] == 0xdeadbeef) && (params[5] == 0xdeadbeef) && (params[6] == 0xdeadbeef)) {
                    VERBOSE("Canceling Poll");
                    params[0] = 0;
                    break;
                }

                // We have to fill in the last fd with the shadow process fd.
                // The size is already expended by the real-time realm.
                int nfd = params[2] + 1;
                struct pollfd* fds =  (struct pollfd*)params[1];
                fds[nfd - 1].fd = this->fd;
                fds[nfd - 1].events = POLLIN;
                params[0] = raw_syscall(7, (uintptr_t)fds, nfd, params[3], 0, 0, 0);
                break;
                }
            case 16:
                if(params[2] == TIOCSPGRP){
                    params[0] = 0;
                    break;
                }
            case 3:
                // Don't let client close the shadow-process!
                if(params[1] == this->fd) {
                    params[0] = 0;
                    break;
                }
                // Fall through
            default:
                errno = 0;
                params[0] = raw_syscall(params[0], params[1], params[2], params[3], params[4], params[5], params[6]);
                curr_errno = errno;
                break;
        }

        _VERBOSE(scdecode.decode(nbr, params + 1, params[0]));

        write(this->fd, &params, sizeof(uint64_t));
    }

    uint64_t exit_reason = params[0];

    if(this->is_main) {

        for( auto thread : threads ) {
            pthread_join(thread->tid, NULL);
            if(thread->tproxy)
                delete thread->tproxy;
            delete thread;
        }

        for( auto mapping : mappings ) {
            delete mapping;
        }
        mappings.erase(mappings.begin(), mappings.end());

        VERBOSE("Main thread exiting");

        exit(exit_reason);
    } else {
        VERBOSE("Thread exiting");
        pthread_exit(NULL);
    }

    // For threads, return;
}


void Proxy::send_remote_signal(int signo) {
    //On transmit, {signo, MSb 1 |  pid}
    ioctl(this->fd, _IOW('k', 8, uint64_t), signo);
}
