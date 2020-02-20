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

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#ifndef __IO_HPP__
#define __IO_HPP__

#define HEADER_SIZE sizeof(packet_header)

enum pkt_type{
    PING,
    PONG,
    RETURN,
    REXEC,
    TRASH,
    MAX_TYPE
};

struct packet_header{
    uint16_t type;
    uint32_t attribute;
    uint32_t length;
} __attribute__((packed));

struct packet{
    struct packet_header hdr;
    std::basic_string<uint8_t> data;
};

class IO {
    public:
        IO(std::string ip_addr, int port, bool verbose);
        virtual ~IO();

        void ping();
        void magic();

        std::basic_string<uint8_t> invoke(pkt_type ty, std::basic_string<uint8_t> & data);

        struct packet recv();
        void send(pkt_type ty, std::basic_string<uint8_t> data);

        int fd;
    private:

        struct sockaddr_in serv_addr;
        bool verbose;
};


#endif // __IO_HPP__
