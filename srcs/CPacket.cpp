#include "../headers/CPacket.h"

#include <iostream>
#include <netinet/if_ether.h>

void print_bytes(const void *object, size_t size)
{
    // This is for C++; in C just drop the static_cast<>() and assign.
    const char * bytes = reinterpret_cast<const char *>(object);
    size_t i;
    for(i = 0; i < size; i++)
    {
        if ((bytes[i] >= 'a' && bytes[i] <= 'z') || (bytes[i] >= 'A' && bytes[i] <= 'Z') || (bytes[i] >= '0' && bytes[i] <= '9'))
            printf("%c", bytes[i]);
        else
            printf(".");
    }
    printf("\n");
}

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

            std::cout << "ETHER_HEADER_LEN: " << std::to_string(sizeof(struct ethhdr)) << " bytes." << std::endl;
            std::cout << "IP_HEADER_LEN: " << std::to_string(this->m_pIPHeader->ihl * 4) << " bytes." << std::endl;
            std::cout << "TCP_HEADER_LEN: " << std::to_string(this->getTCPHeader()->doff * 4) << " bytes." << std::endl;
            std::cout << "DATA_LEN: " << std::to_string(data_len) << std::endl;
            std::cout << "TOTAL_LEN: " << std::to_string(total_len) << " bytes." << std::endl;

            //Passer le header TCP
            buffer = buffer + (this->getTCPHeader()->doff * 4);

            auto parser = new DNSParser();
            parser->parseData(buffer, data_len);
            if (parser->isValiddDNSPacket()) {
                std::cout << "DNS HEADER DETECTED !" << std::endl;
            }

            print_bytes(buffer, data_len);

            auto detector = new httpDetector();
            detector->parseData(buffer, data_len);
            if (detector->isValiddHTTPPacket()) {
                std::cout << "HTTP HEADER DETECTED !" << std::endl;
            }

            break;
        }
        case 17:
            this->setUDPHeader(reinterpret_cast<struct udphdr *>(buffer));
            auto parser = new DNSParser();
            parser->parseData(buffer + sizeof(struct udphdr), ntohs(this->getUDPHeader()->len) - sizeof(struct udphdr));
            if (parser->isValiddDNSPacket()) {
                std::cout << "DNS HEADER DETECTED !" << std::endl;
            }

            auto detector = new httpDetector();
            detector->parseData(buffer + sizeof(struct udphdr), ntohs(this->getUDPHeader()->len) - sizeof(struct udphdr));
            if (detector->isValiddHTTPPacket()) {
                std::cout << "HTTP HEADER DETECTED !" << std::endl;
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
