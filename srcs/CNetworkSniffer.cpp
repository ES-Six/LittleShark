/*
* Created by Enguerrand
*/
#include "../headers/CNetworkSniffer.h"

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
            return "IP";
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

    // En mode AF_PACKETS il faut exclure le header ethernet du buffer
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

    retn->m_protocol = iph->protocol;
    retn->m_length = iph->tot_len;
    retn->m_TTL = iph->ttl;
    retn->m_destination.sin_addr.s_addr = iph->daddr;
    retn->m_source.sin_addr.s_addr = iph->saddr;

    return retn;
}