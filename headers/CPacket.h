#pragma once

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

class C_Packet
{
public:
    int m_protocol;
    int m_length;
    int m_TTL;
    struct sockaddr_in m_source;
    struct sockaddr_in m_destination;


    C_Packet();
    ~C_Packet();
};