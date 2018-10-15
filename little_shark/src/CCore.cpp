/*
* Created by Enguerrand
*/

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <sys/socket.h>
#include <net/ethernet.h>

#include "../header/CCore.h"

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
        std::cerr << "Unable to create the socket: " << strerror(errno) << std::endl;
        return;
    }

    int data_size;
    unsigned char *buffer = (unsigned char *)malloc(65536);
    struct sockaddr *packet_info;
	socklen_t packet_info_size = sizeof(packet_info);

    while(1){
        data_size = recvfrom(sock_raw, buffer, 65536, 0, packet_info, &packet_info_size);
        if(data_size < 0){
            std::cerr << "Failed to get packets: " << strerror(errno) << std::endl;
            return;
        }
        C_Packet *packet = this->m_pNetworkSniffer->Parse(buffer);
        std::cout << "Received packet of type " << this->m_pNetworkSniffer->GetPacketProtocol(packet->m_iProtocol) << std::endl;
        //TODO: Add anything to do with packet here

        if(packet){
            packet = nullptr;
        }
    }

    delete buffer;
}