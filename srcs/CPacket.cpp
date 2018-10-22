#include "../headers/CPacket.h"

#include <iostream>

void CPacket::parseIPv4Protocol(unsigned char *buffer)
{
    this->m_pIPHeader = reinterpret_cast<struct iphdr *>(buffer);
    buffer +=  sizeof(struct iphdr);

    switch(this->m_pIPHeader->protocol)
    {
        case 1:
            this->setICMPHeader(reinterpret_cast<struct icmphdr *>(buffer));
            break;

        case 6:
            this->setTCPHeader(reinterpret_cast<struct tcphdr *>(buffer));
            break;

        case 17:
            this->setUDPHeader(reinterpret_cast<struct udphdr *>(buffer));
            auto parser = new DNSParser();
            parser->parseData(buffer + sizeof(struct udphdr), ntohs(this->getUDPHeader()->len) - sizeof(struct udphdr));
            if (parser->isValiddDNSPacket()) {
                std::cout << "DNS HEADER DETECTED !" << std::endl;
            }
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
