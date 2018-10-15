/*
* Created by Enguerrand
*/
#include "../header/CNetworkSniffer.h"

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

        default:
            return "Unknow";
        break;
    }
}

C_Packet *C_NetworkSniffer::Parse(unsigned char *buffer)
{
    C_Packet *retn = new C_Packet;

    struct iphdr *iph = (struct iphdr*)buffer;

    retn->m_iProtocol = iph->ip_p;
    retn->m_iLength = iph->ip_len;
    retn->m_iTTL = iph->ip_ttl;
    retn->m_sDest = iph->ip_dst;
    retn->m_sSrc = iph->ip_src;

    return retn;
}