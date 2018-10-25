//
// Created by brendan on 25/10/18.
//

#ifndef LITTLE_SHARK_PACKETGENERATOR_H
#define LITTLE_SHARK_PACKETGENERATOR_H

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

class PacketGenerator {
public:
    static const unsigned int WITH_IPV4 = 0b00001;
    static const unsigned int WITH_IPV6 = 0b00010;
    static const unsigned int WITH_ICMP = 0b00100;
    static const unsigned int WITH_UDP  = 0b01000;
    static const unsigned int WITH_TCP  = 0b10000;

    PacketGenerator() = default;
    ~PacketGenerator();

    unsigned char *createPacket(unsigned char *buffer, ssize_t packet_len, unsigned int = PacketGenerator::WITH_IPV4 | PacketGenerator::WITH_UDP);
private:
    unsigned char *m_pPacket = nullptr;
};


#endif //LITTLE_SHARK_PACKETGENERATOR_H
