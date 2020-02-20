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

#include "IO.hpp"

IO::IO(std::string ip_addr, int port, bool verbose) :
    verbose(verbose)
{
    int ret;

    this->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (this->fd < 0) {
        throw std::runtime_error("Failed to create socket");
    }

    memset(&this->serv_addr, '0', sizeof(this->serv_addr));

    this->serv_addr.sin_family = AF_INET;
    this->serv_addr.sin_port = htons(port);
    ret = inet_pton(AF_INET, ip_addr.c_str(), &this->serv_addr.sin_addr);

    if( ret <= 0 ) {
        throw std::runtime_error("Invalid address or port number");
    }

    ret = connect(this->fd, (struct sockaddr *)&this->serv_addr, sizeof(this->serv_addr));
    if( ret < 0 ) {
        throw std::runtime_error("Connection failed with " + std::string(strerror(errno)));
    }

    return;
}

IO::~IO() {
    close(this->fd);
    return;
}

void IO::ping() {
    this->send(PING, std::basic_string<uint8_t>());

    if(this->verbose) std::clog << "PINGED, WAIT PONG...";

    auto pkt = this->recv();

    if(pkt.hdr.type != PONG)
        throw std::runtime_error("Got trash while waiting for PONG");
    if(this->verbose) std::clog << "GOT PONG" << std::endl;
}

void IO::magic() {
    this->send((pkt_type)0xdead, std::basic_string<uint8_t>());

    if(this->verbose) std::clog << "MAGIC sent...";

    auto pkt = this->recv();

    if(pkt.hdr.type != PONG)
        throw std::runtime_error("Got trash while waiting for PONG");
    if(this->verbose) std::clog << "GOT PONG" << std::endl;
}

void IO::send(pkt_type ty, std::basic_string<uint8_t> data) {
    if(this->verbose) std::clog << "Sending length: 0x" << std::hex << data.length() << std::endl;

    struct packet_header hdr;
    hdr.type = ty;
    hdr.attribute = 0;
    hdr.length = data.length();

    write(this->fd, &hdr, HEADER_SIZE);
    write(this->fd, data.c_str(), data.length());
}

struct packet IO::recv() {
    struct packet pkt;
    uint8_t *buf;
    read(this->fd, &pkt.hdr, sizeof(pkt.hdr));
    if(pkt.hdr.length > 0) {
        buf = new uint8_t[pkt.hdr.length * 2];
        read(this->fd, buf, pkt.hdr.length);
        pkt.data = std::basic_string<uint8_t>(buf, pkt.hdr.length);
        delete buf;
    }

    return pkt;
}

std::basic_string<uint8_t> IO::invoke(pkt_type ty, std::basic_string<uint8_t> & data) {
    this->send(ty, data);

    auto ret = this->recv();

    if( ret.hdr.type != RETURN ) {
        throw std::runtime_error("Got trash while waiting for RETURN");
    }

    return ret.data;
}
