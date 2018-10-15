#pragma once

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