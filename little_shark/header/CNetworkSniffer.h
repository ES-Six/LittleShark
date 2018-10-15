/*
* Created by Enguerrand
*/

#pragma once

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include <string>

#ifdef __APPLE__
#define iphdr ip
#endif

#include "CPacket.h"

class C_NetworkSniffer
{
public:
    C_NetworkSniffer();
    ~C_NetworkSniffer();

    std::string GetPacketProtocol(int type);
    C_Packet *Parse(unsigned char *buffer);
};