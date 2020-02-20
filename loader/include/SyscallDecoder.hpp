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

#include <LIEF/LIEF.hpp>

#include "UIO.hpp"
#include "IO.hpp"

#ifndef __SYSCALL_DECODER_HPP__
#define __SYSCALL_DECODER_HPP__

struct syscall_entry {
    char name[33];
    char param_format[16];
    int error_code;
};

class SyscallDecoder {
    public:
        SyscallDecoder(const SyscallDecoder&) = delete;
        SyscallDecoder& operator=(const SyscallDecoder&) = delete;
        SyscallDecoder(SyscallDecoder&&) = delete;
        SyscallDecoder& operator=(SyscallDecoder&&) = delete;

        static SyscallDecoder& get_instance()
        {
            static SyscallDecoder instance(true);
            return instance;
        }

        void decode(uint64_t nbr, uint64_t *params, uint64_t ret);

    protected:
    private:
        SyscallDecoder(bool verbose);
        virtual ~SyscallDecoder();

        bool verbose;
        struct syscall_entry syscall_table[350];
};

#endif // __SYSCALL_DECODER_HPP__
