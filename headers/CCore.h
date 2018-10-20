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
    void printEthernetFrameProtocol(CEthenetFrame *frame);
    void printIPv4FrameProtocol(CEthenetFrame *frame);
    void printTCPProtocol(CPacket *frame);
    void printUDPProtocol(CPacket *frame);

private:
    struct sockaddr saddr;
};