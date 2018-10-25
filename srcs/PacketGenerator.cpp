//
// Created by brendan on 25/10/18.
//

#include "../headers/PacketGenerator.h"

#include <iostream>

PacketGenerator::~PacketGenerator() {
    delete this->m_pPacket;
}

unsigned char *PacketGenerator::createPacket(unsigned char *buffer, ssize_t buffer_len, const unsigned int options) {
    if ((options & PacketGenerator::WITH_IPV4) == PacketGenerator::WITH_IPV4) {
        std::cout << "CREATE PACKET WITH IPV4 HEADER" << std::endl;
    }
    if ((options & PacketGenerator::WITH_IPV6) == PacketGenerator::WITH_IPV6) {
        std::cout << "CREATE PACKET WITH IPV6 HEADER" << std::endl;
    }
    if ((options & PacketGenerator::WITH_ICMP) == PacketGenerator::WITH_ICMP) {
        std::cout << "CREATE PACKET INCLUDING ICMP HEADER" << std::endl;
    }
    if ((options & PacketGenerator::WITH_TCP) == PacketGenerator::WITH_TCP) {
        std::cout << "CREATE PACKET INCLUDING TCP HEADER" << std::endl;
    }
    if ((options & PacketGenerator::WITH_UDP) == PacketGenerator::WITH_UDP) {
        std::cout << "CREATE PACKET INCLUDING UDP HEADER" << std::endl;
    }

}