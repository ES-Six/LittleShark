/*
* Created by Enguerrand
*/
#include "../headers/CNetworkSniffer.h"
#include "../headers/CEthenetFrame.h"

#include <iostream>

std::string C_NetworkSniffer::bufferToStringPrettyfier(const void *object, ssize_t max_len)
{
    std::string packet;
    const char * bytes = reinterpret_cast<const char *>(object);
    for(size_t i = 0; i < max_len; i ++)
    {
        if (bytes[i] >= 33 && bytes[i] <= 126) {
            packet += bytes[i];
        } else {
            packet += '.';
        }
    }

    return packet;
}

CEthenetFrame *C_NetworkSniffer::parse(unsigned char *buffer, ssize_t total_len)
{
    auto ethernetFrame = new CEthenetFrame();

    // Récupération du header ETHERNET
    ethernetFrame->parseEthernetFrame(buffer, total_len);

    return ethernetFrame;
}