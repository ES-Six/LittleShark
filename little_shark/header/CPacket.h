#pragma once

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

class C_Packet
{
public:
    int m_iProtocol;
    int m_iLength;
    int m_iTTL;
    struct in_addr m_sDest;
    struct in_addr m_sSrc;


    C_Packet();
    ~C_Packet();
};