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

#include "UIO.hpp"

std::ifstream::pos_type filesize(std::string filename)
{
    std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
    return in.tellg();
}

UIO::UIO(std::string path, size_t size) : UIO(path, (void*)-1, size, 0) {
    return;
}

UIO::UIO(std::string path, void* start, size_t size, off_t offset) : size(size), start(start) {
    this->path = path;

    this->fd = open(path.c_str(), O_RDWR);
    if (this->fd == -1) {
        perror("open failed");
        throw std::runtime_error("Failed to open: " + path);
    }
    this->control_segment = (uint8_t*)mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (this->control_segment == MAP_FAILED) {
        perror("mmap failed");
        throw std::runtime_error("Failed to map control segment of: " + path);
    }
    if( start == (void*)-1 ) {
        this->data_segment = (uint8_t*)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 4096 + offset);
    } else {
        this->data_segment = (uint8_t*)mmap(start, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 4096 + offset);
    }
    if (this->data_segment == MAP_FAILED) {
        perror("mmap failed");
        std::cout << "Start: " << std::hex << start << "  Offset: " << std::hex << offset << "  Size: " << std::hex << size << std::endl;
        throw std::runtime_error("Failed to map data segment of: " + path);
    }
    close(this->fd);
}

UIO::~UIO() {
    munmap(this->control_segment, 4096);
    munmap(this->data_segment, this->size);
    return;
}

std::basic_string<uint8_t> UIO::memory() {
    return std::basic_string<uint8_t>(this->data_segment, this->size);
}

uint8_t* UIO::raw_memory() {
    return this->data_segment;
}


void UIO::send_irq() {
    *(uint64_t*)(this->control_segment + 4) = 0;
}

void UIO::wait_irq() {
    uint8_t dummy[8];
    read(this->fd, dummy, 4);
}
