//
// Created by brendan on 25/10/18.
//

#include "../headers/PacketGenerator.h"

#include <iostream>
#include <cstring>

#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

PacketGenerator::~PacketGenerator() {
    delete this->m_pPacket;
}

void PacketGenerator::fillEthernetHeader(struct ethhdr *header, const char *src_adr_mac, const char *dst_adr_mac) {
    // Remplir Adresse MAC source et destination
    // Definir le protocol à IPV4
    std::memcpy(header->h_source, ether_aton(src_adr_mac), 6);
    std::memcpy(header->h_dest, ether_aton(dst_adr_mac), 6);
    header->h_proto = htons(ETHERTYPE_IP);
}

void PacketGenerator::fillIPV4Header(struct iphdr *header) {

}

unsigned char *PacketGenerator::createPacket(unsigned char *buffer, ssize_t payload_len, const unsigned int options) {
    // bool forgeIPV4 = ((options & PacketGenerator::WITH_IPV4) == PacketGenerator::WITH_IPV4);
    bool forgeICMP = ((options & PacketGenerator::WITH_ICMP) == PacketGenerator::WITH_ICMP);
    bool forgeTCP = ((options & PacketGenerator::WITH_TCP) == PacketGenerator::WITH_TCP);
    bool forgeUDP = ((options & PacketGenerator::WITH_UDP) == PacketGenerator::WITH_UDP);
    ssize_t packet_len = 0;
    ssize_t ip_next_header_len = 0;
    const char *SRC_ETHER_ADDR = "aa:aa:aa:aa:aa:aa";
    const char *DST_ETHER_ADDR = "bb:bb:bb:bb:bb:bb";
    const char *SRC_IP = "10.38.158.168";
    const char *DST_IP = "127.0.0.1";

    if (!forgeICMP && !forgeTCP && !forgeUDP) {
        forgeUDP = true;
    }

    if (forgeICMP) {
        ip_next_header_len = sizeof(struct icmphdr);
    } else if (forgeTCP) {
        ip_next_header_len = sizeof(struct tcphdr);
    } else {
        ip_next_header_len = sizeof(struct udphdr);
    }

    //Calcul de la taille finale du packet
    packet_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + ip_next_header_len + payload_len;

    auto packet = new unsigned char[packet_len];
    unsigned char *cursor = packet;

    this->fillEthernetHeader(reinterpret_cast<struct ethhdr *>(cursor), SRC_ETHER_ADDR, DST_ETHER_ADDR);

    cursor += sizeof(struct ethhdr);

    return packet;
}