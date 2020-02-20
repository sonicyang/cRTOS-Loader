#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cassert>
#include <iostream>
#include <vector>
#include <stdexcept>
#include <thread>

#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "UIO.hpp"
#include "IO.hpp"

#ifndef __PROXY_HPP__
#define __PROXY_HPP__

class Proxy;

struct thread_s {
    pthread_t tid;
    Proxy* tproxy;
    int tpip[2];
};

class Proxy {
    public:
        Proxy(IO &io, std::string shadow, std::string appmem, bool verbose);
        virtual ~Proxy();

        void rexec(std::string path, std::vector<std::string> argv, std::vector<std::string> envp);
        void run();
        void send_remote_signal(int signo);

        uint64_t get_slot_num() { return slot_num; };

        void self_init();
        void init_sched();
        void init_signal_handling();

    protected:
    private:
        bool is_main;

        IO &io;
        UIO *stack_memory;

        std::string shadow;
        std::string appmem;
        int fd;
        uint64_t slot_num;

        std::list<struct thread_s*> threads;
        std::list<UIO*> mappings;

        int priority;
        int policy;

        bool verbose;
};

#endif // __PROXY_HPP__
