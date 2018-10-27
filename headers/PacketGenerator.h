//
// Created by brendan on 25/10/18.
//

#ifndef LITTLE_SHARK_PACKETGENERATOR_H
#define LITTLE_SHARK_PACKETGENERATOR_H


#include <cstdint>
#include <cstdlib>

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

    void setTarget(const char *, const char *, const char *, const char *);
    unsigned char *createPacket(const unsigned char *buffer, ssize_t packet_len, unsigned int = PacketGenerator::WITH_IPV4 | PacketGenerator::WITH_UDP);
private:
    void fillEthernetHeader(struct ethhdr *, const char *, const char *);
    void fillIPV4Header(struct iphdr *, const char *, const char *, uint16_t, unsigned char);
    unsigned short makeNetworkProtocolsChecksum(unsigned char *data, int len);

    unsigned char *m_pPacket = nullptr;
    const char *src_adr_mac = nullptr; // xx:xx:xx:xx:xx:xx
    const char *dst_adr_mac = nullptr; // yy:yy:yy:yy:yy:yy
    const char *src_adr_ip_v4 = nullptr; // 01.23.45.67
    const char *dst_adr_ip_v4 = nullptr; // 76.54.32.10

    ssize_t createdPacketSize = 0;
};


#endif //LITTLE_SHARK_PACKETGENERATOR_H
