/*
* Created by Enguerrand
*/
#include "../headers/CNetworkSniffer.h"
#include "../headers/CEthenetFrame.h"

#include <iostream>

C_NetworkSniffer::C_NetworkSniffer()
{
}

C_NetworkSniffer::~C_NetworkSniffer()
{

}

CEthenetFrame *C_NetworkSniffer::parse(unsigned char *buffer)
{
    auto ethernetFrame = new CEthenetFrame();

    // Récupération du header ETHERNET
    ethernetFrame->parseEthernetFrame(buffer);

    return ethernetFrame;
}