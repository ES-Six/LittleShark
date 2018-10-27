//
// Created by brendan on 25/10/18.
//

#include "../headers/PacketGenerator.h"

#include <iostream>
#include <cstring>
#include <random>

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

ssize_t PacketGenerator::getCreatedPacketSize() const {
    return this->createdPacketSize;
}

unsigned short PacketGenerator::makeNetworkProtocolsChecksum(unsigned char *data, int len)
{
    long sum = 0;
    auto *temp = (unsigned short *)data;

    while(len > 1){
        sum += *temp++;
        if(sum & 0x80000000) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        len -= 2;
    }

    if(len) {
        sum += static_cast<unsigned short>(*(reinterpret_cast<unsigned char *>(temp)));
    }

    while(sum>>16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return static_cast<unsigned short>(~sum);
}

void PacketGenerator::fillEthernetHeader(struct ethhdr *header, const char *src_adr_mac, const char *dst_adr_mac) {
    // Remplir Adresse MAC source et destination
    // Definir le protocol à IPV4
    std::memcpy(header->h_source, ether_aton(src_adr_mac), 6);
    std::memcpy(header->h_dest, ether_aton(dst_adr_mac), 6);
    header->h_proto = htons(ETHERTYPE_IP);
}

void PacketGenerator::fillIPV4Header(struct iphdr *header, const char *src_adr_ip_v4, const char *dst_adr_ip_v4, uint16_t tot_len, unsigned char protocol) {
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<uint16_t > dist(1, 65535);

    header->version = 4;
    header->ihl = (sizeof(struct iphdr)) / 4 ;
    header->tos = 0;
    header->tot_len = tot_len;
    header->id = htons(dist(mt));
    header->frag_off = 0;
    header->ttl = 64;
    header->protocol = protocol;
    header->check = 0; //Checksum va ici
    header->saddr = inet_addr(src_adr_ip_v4);
    header->daddr = inet_addr(dst_adr_ip_v4);

    // Some de contrôle du header IP
    header->check = makeNetworkProtocolsChecksum(reinterpret_cast<unsigned char *>(header), header->ihl * 4);
}

void PacketGenerator::setTarget(const char *src_adr_mac, const char *dst_adr_mac, const char *src_adr_ip_v4, const char *dst_adr_ip_v4) {
    this->src_adr_mac = src_adr_mac;
    this->dst_adr_mac = dst_adr_mac;
    this->src_adr_ip_v4 = src_adr_ip_v4;
    this->dst_adr_ip_v4 = dst_adr_ip_v4;

}

unsigned char *PacketGenerator::createPacket(const unsigned char *buffer, ssize_t payload_len, const unsigned int options) {
    // bool forgeIPV4 = ((options & PacketGenerator::WITH_IPV4) == PacketGenerator::WITH_IPV4);
    bool forgeICMP = ((options & PacketGenerator::WITH_ICMP) == PacketGenerator::WITH_ICMP);
    bool forgeTCP = ((options & PacketGenerator::WITH_TCP) == PacketGenerator::WITH_TCP);
    bool forgeUDP = ((options & PacketGenerator::WITH_UDP) == PacketGenerator::WITH_UDP);
    ssize_t packet_len = 0;
    ssize_t ip_next_header_len = 0;
    unsigned char ip_protocol = 0;

    if (!this->src_adr_mac || !this->dst_adr_mac || !this->src_adr_ip_v4 || !this->dst_adr_ip_v4) {
        std::cerr << "Error : target IP / MAC address or source IP / MAC address not specified !" << std::endl;
        return nullptr;
    }

    if (!forgeICMP && !forgeTCP && !forgeUDP) {
        std::cerr << "Error : You must specify a packet type (ICMP / TCP / UDP) to forge" << std::endl;
        return nullptr;
    }

    if (forgeICMP) {
        ip_next_header_len = sizeof(struct icmphdr);
        ip_protocol = IPPROTO_ICMP;
    } else if (forgeTCP) {
        ip_next_header_len = sizeof(struct tcphdr);
        ip_protocol = IPPROTO_TCP;
    } else {
        ip_next_header_len = sizeof(struct udphdr);
        ip_protocol = IPPROTO_UDP;
    }

    //Calcul de la taille finale du packet
    packet_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + ip_next_header_len + payload_len;

    this->createdPacketSize = packet_len;

    auto packet = new unsigned char[packet_len];
    unsigned char *cursor = packet;

    this->fillEthernetHeader(reinterpret_cast<struct ethhdr *>(cursor), this->src_adr_mac, this->dst_adr_mac);

    cursor += sizeof(struct ethhdr);

    this->fillIPV4Header(reinterpret_cast<struct iphdr *>(cursor), this->src_adr_ip_v4, this->dst_adr_ip_v4, htons(packet_len - sizeof(struct ethhdr)), ip_protocol);

    cursor += sizeof(struct iphdr);

    if (forgeICMP) {
        // this->fillICMPv4Header(reinterpret_cast<struct icmphdr *>(cursor));
        cursor += sizeof(struct icmphdr);
    } else if (forgeTCP) {
        // this->fillTCPHeader(reinterpret_cast<struct tcphdr *>(cursor));
        cursor += sizeof(struct tcphdr);
    } else {
        // this->fillTCPHeader(reinterpret_cast<struct udphdr *>(cursor));
        cursor += sizeof(struct udphdr);
    }

    // this->fillPayload();

    return packet;
}