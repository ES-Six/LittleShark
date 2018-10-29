#include "CPacket.h"

#include <iostream>
#include <netinet/if_ether.h>

void CPacket::parseIPv4Protocol(unsigned char *buffer, ssize_t total_len)
{
    this->m_pIPHeader = reinterpret_cast<struct iphdr *>(buffer);

    //Passer le header IP
    buffer += (this->m_pIPHeader->ihl * 4);

    switch(this->m_pIPHeader->protocol)
    {
        case 1:
            this->setICMPHeader(reinterpret_cast<struct icmphdr *>(buffer));
            break;

        case 6: {
            this->setTCPHeader(reinterpret_cast<struct tcphdr *>(buffer));

            ssize_t data_len = total_len - sizeof(struct ethhdr) - (this->m_pIPHeader->ihl * 4) - (this->getTCPHeader()->doff * 4);

            if (data_len == 0)
                return;

            //Passer le header TCP
            buffer = buffer + (this->getTCPHeader()->doff * 4);

            // print_bytes(buffer, data_len);

            this->dnsParser.parseData(buffer, data_len);
            this->detectorHTTP.parseData(buffer, data_len);

            break;
        }
        case 17:
            this->setUDPHeader(reinterpret_cast<struct udphdr *>(buffer));

            this->dnsParser.parseData(buffer + sizeof(struct udphdr), ntohs(this->getUDPHeader()->len) - sizeof(struct udphdr));
            this->detectorHTTP.parseData(buffer + sizeof(struct udphdr), ntohs(this->getUDPHeader()->len) - sizeof(struct udphdr));

            break;
    }
}

struct icmphdr *CPacket::getICMPHeader() const
{
    return this->m_pICMPHeader;
}

struct tcphdr *CPacket::getTCPHeader() const
{
    return this->m_pTCPHeader;
}

struct udphdr *CPacket::getUDPHeader() const
{
    return this->m_pUDPHeader;
}

void CPacket::setICMPHeader(struct icmphdr *header)
{
    this->m_pICMPHeader = header;
}

void CPacket::setTCPHeader(struct tcphdr *header)
{
    this->m_pTCPHeader = header;
}

void CPacket::setUDPHeader(struct udphdr *header)
{
    this->m_pUDPHeader = header;
}

bool CPacket::isICMPv4Protocol() const
{
    if (this->m_pIPHeader != nullptr) {
        return this->m_pIPHeader->protocol == 1;
    } else {
        return false;
    }
}

bool CPacket::isTCPProtocol() const
{
    if (this->m_pIPHeader != nullptr) {
        return this->m_pIPHeader->protocol == 6;
    } else {
        return false;
    }
}

bool CPacket::isUDPProtocol() const
{
    if (this->m_pIPHeader != nullptr) {
        return this->m_pIPHeader->protocol == 17;
    } else {
        return false;
    }
}

const DNSParser &CPacket::getDNSParser() const {
    return this->dnsParser;
}

const httpDetector &CPacket::getHTTPDetector() const {
    return this->detectorHTTP;
}
