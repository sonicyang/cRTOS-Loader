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
#include "IO.hpp"
#include "BinLoader.hpp"
#include "Proxy.hpp"

#define USEC_PER_SEC    1000000
#define NSEC_PER_SEC    1000000000

std::string readenv(std::string in) {
    if(std::getenv(in.c_str()) != NULL){
        return std::string(std::getenv(in.c_str()));
    }else{
        throw std::runtime_error("Must specify environment variable: " + in);
    }
    return std::string("NULL");
}

static inline long calcdiff(struct timespec t1, struct timespec t2)
{
    long diff;
    diff = NSEC_PER_SEC * ((int) t1.tv_sec - (int) t2.tv_sec);
    diff += ((int) t1.tv_nsec - (int) t2.tv_nsec);
    return diff;
}

int main(int argc, char *argv[]) {
    std::string sysmap_uio = readenv("SYSMAP");
    struct timespec now, next;

    auto uio = UIO(sysmap_uio, SYSMAP_SIZE);

    while(1){

        clock_gettime(CLOCK_MONOTONIC, &next);

        uio.send_irq();
        uio.wait_irq();
        clock_gettime(CLOCK_MONOTONIC, &now);

        std::cout << calcdiff(now, next) << std::endl;

        usleep(1000000);
    }


    return 0;
}
