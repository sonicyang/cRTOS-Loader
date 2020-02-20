#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cassert>
#include <iostream>
#include <vector>
#include <stdexcept>

#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <LIEF/LIEF.hpp>

#ifndef __UIO_HPP__
#define __UIO_HPP__

#define ATTR_NONE 0x0
#define ATTR_MORE 0x1

#define SYSMAP_SIZE    0x20000
#define APPMEM_START   0x01000000
#define APPMEM_SIZE    0x33000000
#define STACKMEM_START 0x34000000
#define STACKMEM_SIZE  0x08000000

//#define APPMEM_SIZE    0x13000000
//#define STACKMEM_START 0x18000000
//#define STACKMEM_SIZE  0x04000000

class UIO {
    public:
        UIO(std::string path, size_t size);
        UIO(std::string path, void* start, size_t size, off_t offset);
        virtual ~UIO();

        std::basic_string<uint8_t> memory();
        uint8_t* raw_memory();

        void send_irq();
        void wait_irq();

        std::string get_path() { return this->path; };

    private:
        std::string path;

        size_t size;
        void* start;
        off_t offset;

        int fd;
        uint8_t* control_segment;
        uint8_t* data_segment;

};


#endif // __UIO_HPP__
