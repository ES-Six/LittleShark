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

unsigned short PacketGenerator::IPTCPChecksum(unsigned char *data, int len)
{
    long sum = 0;
    auto *temp = reinterpret_cast<unsigned short *>(data);

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

unsigned short PacketGenerator::icmpChecksum(unsigned short *ptr, int nbytes)
{
    long sum;
    u_short oddbyte;
    u_short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) & oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return (answer);
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
    header->check = 0;
    header->saddr = inet_addr(src_adr_ip_v4);
    header->daddr = inet_addr(dst_adr_ip_v4);

    // Some de contrôle du header IP
    header->check = IPTCPChecksum(reinterpret_cast<unsigned char *>(header), header->ihl * 4);
}

void PacketGenerator::fillICMPv4Header(struct icmphdr *header, ssize_t payload_len) {
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<uint16_t > dist(1, 65535);

    header->type = ICMP_ECHO;
    header->code = 0;
    header->un.echo.sequence = dist(mt);
    header->un.echo.id = dist(mt);
    header->checksum = this->icmpChecksum(reinterpret_cast<unsigned short *>(header), sizeof(struct icmphdr) + payload_len);
}

void PacketGenerator::fillTCPHeader(struct tcphdr *header, struct iphdr *ipheadr, const unsigned char *payload, ssize_t payload_len) {
    header->source = htons(this->src_port);
    header->dest = htons(this->dst_port);
    header->seq = htonl(111);
    header->ack_seq = htonl(111);
    header->res1 = 0;
    header->doff = (sizeof(struct tcphdr)) / 4;
    header->syn = 1;
    header->window = htons(100);
    header->check = 0;
    header->urg_ptr = 0;

    auto tcp_segment_len = static_cast<uint16_t >(ntohs(ipheadr->tot_len) - ipheadr->ihl * 4);
    int total_header_len = sizeof(struct tcpPseudoHeader) + tcp_segment_len;
    auto temporary_buffer = new unsigned char[total_header_len];

    auto tcp_pseudo_header = reinterpret_cast<struct tcpPseudoHeader *>(temporary_buffer);
    tcp_pseudo_header->src_ip = ipheadr->saddr;
    tcp_pseudo_header->dst_ip = ipheadr->daddr;
    tcp_pseudo_header->rsv = 0;
    tcp_pseudo_header->proto = ipheadr->protocol;
    tcp_pseudo_header->tcp_len = htons(tcp_segment_len);

    // Append TCP header
    std::memcpy((temporary_buffer + sizeof(struct tcpPseudoHeader)), reinterpret_cast<void *>(header), static_cast<size_t>(header->doff * 4));
    // Append datas
    std::memcpy((temporary_buffer + sizeof(struct tcpPseudoHeader) + header->doff * 4), payload, static_cast<size_t>(payload_len));

    header->check = this->IPTCPChecksum(reinterpret_cast<unsigned char *>(tcp_pseudo_header), total_header_len);

    delete[] tcp_pseudo_header;

    std::cout << std::to_string(header->check) << std::endl;
}

void PacketGenerator::fillUDPHeader(struct udphdr *header, struct iphdr *ipheadr, ssize_t payload_len) {
    header->source = htons(this->src_port);
    header->dest = htons(this->dst_port);
    header->len = htons(sizeof(struct udphdr) + payload_len);
    header->check = 0;
}

void PacketGenerator::setTarget(const char *src_adr_mac, const char *dst_adr_mac, const char *src_adr_ip_v4, const char *dst_adr_ip_v4, uint16_t src_port, uint16_t dst_port) {
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

    auto packet = new unsigned char[packet_len];
    unsigned char *cursor = packet;

    this->fillEthernetHeader(reinterpret_cast<struct ethhdr *>(cursor), this->src_adr_mac, this->dst_adr_mac);

    cursor += sizeof(struct ethhdr);

    auto ipheadr = reinterpret_cast<struct iphdr *>(cursor);
    this->fillIPV4Header(reinterpret_cast<struct iphdr *>(cursor), this->src_adr_ip_v4, this->dst_adr_ip_v4, htons(packet_len - sizeof(struct ethhdr)), ip_protocol);

    cursor += sizeof(struct iphdr);

    if (forgeICMP) {
        this->fillICMPv4Header(reinterpret_cast<struct icmphdr *>(cursor), payload_len);
        std::memcpy((packet + sizeof(struct ethhdr) + ipheadr->ihl * 4 + sizeof(struct icmphdr)), buffer,
                    static_cast<size_t>(payload_len));
    } else if (forgeTCP) {
        this->fillTCPHeader(reinterpret_cast<struct tcphdr *>(cursor), ipheadr, buffer, payload_len);
        std::memcpy((packet + sizeof(struct ethhdr) + ipheadr->ihl * 4 + reinterpret_cast<struct tcphdr *>(cursor)->doff * 4), buffer,
                    static_cast<size_t>(payload_len));
    } else {
        this->fillUDPHeader(reinterpret_cast<struct udphdr *>(cursor), ipheadr, payload_len);
        std::memcpy((packet + sizeof(struct ethhdr) + ipheadr->ihl * 4 + sizeof(struct udphdr)), buffer,
                    static_cast<size_t>(payload_len));
        reinterpret_cast<struct udphdr *>(cursor)->check = this->IPTCPChecksum(cursor, static_cast<uint16_t >(ntohs(ipheadr->tot_len) - ipheadr->ihl * 4) + sizeof(struct udphdr));
    }

    this->createdPacketSize = sizeof(struct ethhdr) + ntohs(ipheadr->tot_len);

    return packet;
}