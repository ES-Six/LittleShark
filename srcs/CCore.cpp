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

#include "../headers/CCore.h"

C_Core::C_Core()
{
    m_pNetworkSniffer = new C_NetworkSniffer();
}

C_Core::~C_Core()
{
    if(m_pNetworkSniffer){
        delete m_pNetworkSniffer;
    }
}

void C_Core::Process()
{
    if(!m_pNetworkSniffer){
        return;
    }

    int sock_raw = socket(PF_INET, SOCK_RAW, 1);//TODO: Set the flag to capture all packets, not only ICMP
    if(sock_raw == -1){
        std::cerr << "Unable to create the socket: " << std::strerror(errno) << std::endl;
        return;
    }

    ssize_t data_size;
    unsigned char *buffer = (unsigned char *)malloc(65536);
	socklen_t sockaddr_size = sizeof(saddr);

    while(1){
        data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &sockaddr_size);
        if(data_size < 0){
            std::cerr << "Failed to get packets: " << std::strerror(errno) << std::endl;
            return;
        }
        C_Packet *packet = this->m_pNetworkSniffer->Parse(buffer);
        std::cout << "Received packet of type " << this->m_pNetworkSniffer->GetPacketProtocol(packet->m_protocol) << std::endl;
        //TODO: Add anything to do with packet here

        if(packet){
            packet = nullptr;
        }
    }

    delete buffer;
}