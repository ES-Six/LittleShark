//
// Created by brendan on 25/10/18.
//

#ifndef LITTLE_SHARK_PACKETGENERATOR_H
#define LITTLE_SHARK_PACKETGENERATOR_H


#include <cstdint>
#include <cstdlib>

struct tcpPseudoHeader {
    uint32_t src_ip;
    uint32_t dst_ip;
    u_char rsv;
    u_char proto;
    uint16_t tcp_len;
};

class PacketGenerator {
public:
    static const unsigned int WITH_IPV4 = 0b00001;
    // static const unsigned int WITH_IPV6 = 0b00010;
    static const unsigned int WITH_ICMP = 0b00100;
    static const unsigned int WITH_UDP  = 0b01000;
    static const unsigned int WITH_TCP  = 0b10000;

    ssize_t getCreatedPacketSize() const;

    PacketGenerator() = default;
    ~PacketGenerator();

    void setTarget(const char *, const char *, const char *, const char *, uint16_t = 4567, uint16_t = 7654);
    unsigned char *createPacket(const unsigned char *buffer, ssize_t packet_len, unsigned int = PacketGenerator::WITH_IPV4 | PacketGenerator::WITH_UDP);
private:
    void fillEthernetHeader(struct ethhdr *, const char *, const char *);
    void fillIPV4Header(struct iphdr *, const char *, const char *, uint16_t, unsigned char);
    unsigned short IPTCPChecksum(unsigned char *, int);
    void fillICMPv4Header(struct icmphdr *, ssize_t);
    unsigned short icmpChecksum(unsigned short *ptr, int nbytes);
    void fillTCPHeader(struct tcphdr *header, struct iphdr *, const unsigned char *, ssize_t);

    unsigned char *m_pPacket = nullptr;
    const char *src_adr_mac = nullptr; // xx:xx:xx:xx:xx:xx
    const char *dst_adr_mac = nullptr; // yy:yy:yy:yy:yy:yy
    const char *src_adr_ip_v4 = nullptr; // 01.23.45.67
    const char *dst_adr_ip_v4 = nullptr; // 76.54.32.10
    uint16_t src_port = 4567;
    uint16_t dst_port = 7654;

    ssize_t createdPacketSize = 0;
};


#endif //LITTLE_SHARK_PACKETGENERATOR_H
