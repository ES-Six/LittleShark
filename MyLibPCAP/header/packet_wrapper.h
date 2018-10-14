//
// Created by brendan on 13/10/18.
//

#ifndef MY_LIBPCAP_PACKET_WRAPPER_H
#define MY_LIBPCAP_PACKET_WRAPPER_H

#include "pcap_file_headers.h"

namespace MyLibPCAP
{
    class PacketWrapper
    {
    public:
        PacketWrapper();
        ~PacketWrapper();
        void setPacketHeader(pcap_pkthdr *);
        void setPacketContent(char *);
        pcap_pkthdr *getPacketHeader() const;
        char *getPacketContent() const;
    private:
        char *packetContent = nullptr;
        pcap_pkthdr *packetHeader = nullptr;
    };
}

#endif //MY_LIBPCAP_PACKET_WRAPPER_H
