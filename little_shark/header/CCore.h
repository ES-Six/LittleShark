/*
* Created by Enguerrand
*/

#pragma once

#include "CNetworkSniffer.h"
#include "CPacket.h"

class C_Core
{
    public:
    C_NetworkSniffer *m_pNetworkSniffer;


    C_Core();
    ~C_Core();
    void Process();
};