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
#include <signal.h>

#include "UIO.hpp"
#include "IO.hpp"
#include "Proxy.hpp"

static std::string get_filename(const std::string& s) {

   char sep = '/';

   size_t i = s.rfind(sep, s.length());
   if (i != std::string::npos) {
      return(s.substr(i+1, s.length() - i));
   }

   return("");
}

void print_usage() {
    std::cout << "Usage: loader <optional env> <elf file> ..." << std::endl;
    std::cout << "Environment variable SYSMAP and APPMEM must be set to corresponding uio device" << std::endl;
}

std::string readenv(std::string in, std::string def) {
    if(std::getenv(in.c_str()) != NULL){
        return std::string(std::getenv(in.c_str()));
    }else{
        return def;
    }
    return std::string("NULL");
}

int main(int argc, char *argv[], char *envp[]) {
    bool verbose = (readenv("VERBOSE", "0") == "1");
    bool magic = (readenv("MAGIC", "0") == "1");

    if(magic){
        auto io = IO("172.16.0.2", 42, verbose);
        io.magic();
        return 0;
    }

    // Early declaration for additional envs
    int i;
    std::vector<std::string> llenvv;
    for( i = 1; i < argc; i++ ) {
        auto curr = std::string(argv[i]);
        if(curr.find('=') != std::string::npos) {
            // Take a string with '=' as env
            llenvv.push_back(curr);
        } else {
            break;
        }
    }

    // Nothing left?
    if( argc - i < 1 ) {
        print_usage();
        exit(1);
    }

    std::string sysmap_uio = readenv("SYSMAP", "/dev/uio0");
    std::string appmem_uio = readenv("APPMEM", "/dev/uio1");
    std::string shadow = readenv("SHADOWPROC", "/dev/shadow-process");
    std::string elf_filename(argv[i++]);


    auto io = IO("172.16.0.2", 42, verbose);
    auto pxy = Proxy(io, shadow, appmem_uio, verbose);

    if(verbose) std::clog << "Testing Communication..." << std::endl;
    io.ping();

    std::vector<std::string> llargv;
    for( ; i < argc; i++ ) {
        llargv.push_back(std::string(argv[i]));
    }

    for( i = 0; envp[i]; i++ ) {
        llenvv.push_back(std::string(envp[i]));
    }

    //auto loader = BinLoader(sysmap_uio, appmem_uio, io, verbose);
    //auto app = loader.load(elf_filename, llargv, llenvv, tcb);

    // This is the convention
    llargv.insert(llargv.begin(), elf_filename);

    // Reserve the Lower portion of the memory to prevent libc and kernel being funky
    if(!mmap((void*)APPMEM_START, APPMEM_SIZE, PROT_NONE, MAP_SHARED, 0, 0)){
        throw std::runtime_error("Unable to reserve the low memory space!");
    }


    pxy.rexec(elf_filename, llargv, llenvv);

    return 0;
}
