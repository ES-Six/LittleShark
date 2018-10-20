/*
* Created by Enguerrand
*/
#include "../headers/CNetworkSniffer.h"

#include <iostream>

C_NetworkSniffer::C_NetworkSniffer()
{
}

C_NetworkSniffer::~C_NetworkSniffer()
{

}

std::string C_NetworkSniffer::GetPacketProtocol(int type)
{
    switch(type)
    {
        case 0:
            return "HOPOPT";
        break;

        case 1:
            return "ICMP";
        break;

        case 6:
            return "TCP";
        break;

        case 17:
            return "UDP";
        break;

        default:
            return std::string("UNKNOWN : ")+std::to_string(type);
        break;
    }
}

C_Packet *C_NetworkSniffer::Parse(unsigned char *buffer)
{
    C_Packet *retn = new C_Packet();

    // Récupération du header ETHERNET
    struct ethhdr *ethernet_frame = (struct ethhdr*)buffer;
    __be16 ethernet_protocol = htons(ethernet_frame->h_proto);
    if (ethernet_protocol == ETH_P_ARP) {
        std::cout << "Ethernet frame with ARP Protocol" << std::endl;
    } else if (ethernet_protocol == ETH_P_IP) {
        std::cout << "Ethernet frame with IP protool" << std::endl;
    } else if (ethernet_protocol == ETH_P_IPV6) {
        std::cout << "Ethernet frame with IP protool" << std::endl;
    } else {
        std::cout << "Unknown OSI level 2 protool : " << std::hex << ethernet_protocol << std::endl;
    }

    // En mode AF_PACKETS nous avons acces au header ethernet avant le header IP
    buffer +=  sizeof(struct ethhdr);
    struct iphdr *iph = (struct iphdr*)(buffer);

    retn->m_protocol = iph->protocol;
    retn->m_length = iph->tot_len;
    retn->m_TTL = iph->ttl;
    retn->m_destination.sin_addr.s_addr = iph->daddr;
    retn->m_source.sin_addr.s_addr = iph->saddr;

    return retn;
}