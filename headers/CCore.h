/*
* Created by Enguerrand
*/

#pragma once

#include "CNetworkSniffer.h"
#include "CEthenetFrame.h"

class C_Core
{
public:
    C_NetworkSniffer *m_pNetworkSniffer;
    C_Core();
    ~C_Core();

    void Process();
    void printEthernetFrameProtocol(CEthenetFrame *, ssize_t);
    void printIPv4FrameProtocol(CEthenetFrame *);
    void printTCPProtocol(CPacket *);
    void printUDPProtocol(CPacket *);

private:
    struct sockaddr saddr;
};