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

void C_Core::printEthernetFrameProtocol(CEthenetFrame *frame) {
    std::cout << "Received ethernet frame containing protocol";
    if (frame->isARPProtocol()) {
        std::cout << " ARP." << std::endl;
    } else if (frame->isIPv4Protocol()) {
        std::cout << " IP v4 ";
        this->printIPv4FrameProtocol(frame);
    } else if (frame->isIPv6Protocol()) {
        std::cout << " IP v6." << std::endl;
    } else
        std::cout << " unknown." << std::endl;
}

void C_Core::printIPv4FrameProtocol(CEthenetFrame *frame)
{
    std::cout << "and containing ";

    if (frame->getCPacket() != nullptr && frame->getCPacket()->isICMPv4Protocol()) {
        std::cout << " an ICMPv4 packet." << std::endl;
    } else if (frame->getCPacket() != nullptr && frame->getCPacket()->isTCPProtocol()) {
        std::cout << " a TCP packet." << std::endl;
        this->printTCPProtocol(frame->getCPacket());
    } else if (frame->getCPacket() != nullptr && frame->getCPacket()->isUDPProtocol()) {
        std::cout << " an UDP packet." << std::endl;
        this->printUDPProtocol(frame->getCPacket());
    } else if (frame->getCPacket() != nullptr) {
        std::cout << "an unknown packet." << std::endl;
    } else {
        std::cout << "nothing at all." << std::endl;
    }
}

void C_Core::printTCPProtocol(CPacket *frame)
{

}

void C_Core::printUDPProtocol(CPacket *frame)
{

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
        this->printEthernetFrameProtocol(frame);

        //TODO: Add anything to do with packet here
        delete frame;
    }

    delete buffer;
}