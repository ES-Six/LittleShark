/*
* Created by Enguerrand
*/

#include <cstring>
#include <cmath>
#include <cstdio>
#include <cerrno>
#include <stdlib.h>
#include <iostream>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>

#include "../headers/CCore.h"

C_Core::C_Core()
{
    m_pNetworkSniffer = new C_NetworkSniffer();
}

C_Core::~C_Core()
{
    delete m_pNetworkSniffer;
}

void C_Core::printEthernetFrameProtocol(CEthenetFrame *frame, ssize_t total_len) {
    // std::cout << std::endl << "Received following ethernet frame :" << std::endl;
    // std::cout << C_NetworkSniffer::bufferToStringPrettyfier(frame->getEthernetFrame(), total_len) << std::endl << std::endl;;
    if (frame->isARPProtocol()) {
        std::cout << "Buffer contain ARP DATAS." << std::endl;
    } else if (frame->isIPv4Protocol()) {
        std::cout << "Buffer contain IP v4 header";
        this->printIPv4FrameProtocol(frame);
    } else if (frame->isIPv6Protocol()) {
        std::cout << "Buffer contain IP v6 header." << std::endl;
    } else
        std::cout << "Buffer contain unknown datas." << std::endl;
}

void C_Core::printIPv4FrameProtocol(CEthenetFrame *frame)
{
    if (frame->getCPacket() != nullptr && frame->getCPacket()->isICMPv4Protocol()) {
        std::cout << " and contain an ICMPv4 packet." << std::endl;
    } else if (frame->getCPacket() != nullptr && frame->getCPacket()->isTCPProtocol()) {
        std::cout << " and contain a TCP packet." << std::endl;
        this->printTCPProtocol(frame->getCPacket());
    } else if (frame->getCPacket() != nullptr && frame->getCPacket()->isUDPProtocol()) {
        std::cout << " and contain an UDP packet." << std::endl;
        this->printUDPProtocol(frame->getCPacket());
    } else if (frame->getCPacket() != nullptr) {
        std::cout << " and contain unknown datas." << std::endl;
    } else {
        std::cout << "nothing at all." << std::endl;
    }
}

void C_Core::printTCPProtocol(CPacket *cpacket)
{
    if (cpacket->getHTTPDetector().isValiddHTTPPacket()) {
        if (cpacket->getHTTPDetector().isHTTPRequest()) {
            std::cout << "The packet contain an HTTP Request Header :" << std::endl;
            std::cout << "Protocol : " << cpacket->getHTTPDetector().getProtocolVersion() << std::endl;
            std::cout << "Method : " << cpacket->getHTTPDetector().getMethod() << std::endl;
            std::cout << "Url : " << cpacket->getHTTPDetector().getUrl() << std::endl;
        } else if (cpacket->getHTTPDetector().isHTTPResponse()) {
            std::cout << "The packet contain an HTTP Response Header :" << std::endl;
            std::cout << "Protocol : " << cpacket->getHTTPDetector().getProtocolVersion() << std::endl;
            std::cout << "Response code : " << cpacket->getHTTPDetector().getReturnCode() << std::endl;
        }
    } else if (cpacket->getDNSParser().isValiddDNSPacket()) {
        if (cpacket->getDNSParser().isDNSQuery()) {
            std::cout << "The packet contain a DNS QUERY Header :" << std::endl;
            std::cout << "Domain: " << cpacket->getDNSParser().getDomainName() << std::endl;
            std::cout << "Type: " << DNSParser::dnsQueryTypeToStr(cpacket->getDNSParser().getQueryType()) << std::endl;
        } else if (cpacket->getDNSParser().isDNSAnswer()) {
            std::cout << "The packet contain a DNS ANSWER Header :" << std::endl;
            if (cpacket->getDNSParser().getRecords().empty()) {
                std::cout << "NO RECORDS TO DISPLAY" << std::endl;
            }
            for (const std::string &record : cpacket->getDNSParser().getRecords()) {
                std::cout << DNSParser::dnsQueryTypeToStr(cpacket->getDNSParser().getQueryType())  << " " << cpacket->getDNSParser().getDomainName() << " " << record << std::endl;
            }
        }
    }
}

void C_Core::printUDPProtocol(CPacket *cpacket)
{
    if (cpacket->getDNSParser().isValiddDNSPacket()) {
        if (cpacket->getDNSParser().isDNSQuery()) {
            std::cout << "The packet contain a DNS QUERY Header :" << std::endl;
            std::cout << "Domain: " << cpacket->getDNSParser().getDomainName() << std::endl;
            std::cout << "Type: " << DNSParser::dnsQueryTypeToStr(cpacket->getDNSParser().getQueryType()) << std::endl;
        } else if (cpacket->getDNSParser().isDNSAnswer()) {
            std::cout << "The packet contain a DNS ANSWER Header :" << std::endl;
            if (cpacket->getDNSParser().getRecords().empty()) {
                std::cout << "NO RECORDS TO DISPLAY" << std::endl;
            }
            for (const std::string &record : cpacket->getDNSParser().getRecords()) {
                std::cout << DNSParser::dnsQueryTypeToStr(cpacket->getDNSParser().getQueryType())  << " " << cpacket->getDNSParser().getDomainName() << " " << record << std::endl;
            }
        }
    } else if (cpacket->getHTTPDetector().isValiddHTTPPacket()) {
        if (cpacket->getHTTPDetector().isHTTPRequest()) {
            std::cout << "The packet contain an HTTP Request Header :" << std::endl;
            std::cout << "Protocol : " << cpacket->getHTTPDetector().getProtocolVersion() << std::endl;
            std::cout << "Method : " << cpacket->getHTTPDetector().getMethod() << std::endl;
            std::cout << "Url : " << cpacket->getHTTPDetector().getUrl() << std::endl;
        } else if (cpacket->getHTTPDetector().isHTTPResponse()) {
            std::cout << "The packet contain an HTTP Response Header :" << std::endl;
            std::cout << "Protocol : " << cpacket->getHTTPDetector().getProtocolVersion() << std::endl;
            std::cout << "Response code : " << cpacket->getHTTPDetector().getReturnCode() << std::endl;
        }
    }
}

void C_Core::Process()
{
    if(!m_pNetworkSniffer){
        return;
    }

    // TODO: Set the flag to capture all packets
    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock_raw == -1){
        std::cerr << "Unable to create the socket: " << std::strerror(errno) << std::endl;
        return;
    }

    // 65535 is the maximum packet size of a TCP packet
    ssize_t total_len;
    auto buffer = new unsigned char[65536];
	socklen_t sockaddr_size = sizeof(saddr);
    while(1){
        memset(buffer, 0, 65536);
        total_len = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &sockaddr_size);
        // print_bytes(buffer, total_len);
        if(total_len < 0){
            std::cerr << "Failed to get packets: " << std::strerror(errno) << std::endl;
            return;
        }
        CEthenetFrame *frame = this->m_pNetworkSniffer->parse(buffer, total_len);
        this->printEthernetFrameProtocol(frame, total_len);

        //TODO: Add anything to do with packet here
        delete frame;
    }

    delete buffer;
}