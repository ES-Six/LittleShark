#pragma once

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "DNSParser.h"
#include "httpDetector.h"

class CPacket
{
public:
    CPacket() = default;
    ~CPacket() = default;

    void parseIPv4Protocol(unsigned char *, ssize_t);

    struct icmphdr *getICMPHeader() const;
    struct tcphdr *getTCPHeader() const;
    struct udphdr *getUDPHeader() const;
    const DNSParser &getDNSParser() const;
    const httpDetector &getHTTPDetector() const;

    void setICMPHeader(struct icmphdr *);
    void setTCPHeader(struct tcphdr *);
    void setUDPHeader(struct udphdr *);

    bool isICMPv4Protocol() const;
    bool isTCPProtocol() const;
    bool isUDPProtocol() const;
private:
    DNSParser dnsParser;
    httpDetector detectorHTTP;
    struct iphdr *m_pIPHeader = nullptr;
    struct icmphdr *m_pICMPHeader = nullptr;
    struct tcphdr *m_pTCPHeader = nullptr;
    struct udphdr *m_pUDPHeader = nullptr;
};