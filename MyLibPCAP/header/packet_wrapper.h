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
        void setPacketContent(unsigned char *);
        pcap_pkthdr *getPacketHeader() const;
        unsigned char *getPacketContent() const;
    private:
        unsigned char *packetContent = nullptr;
        pcap_pkthdr *packetHeader = nullptr;
    };
}

#endif //MY_LIBPCAP_PACKET_WRAPPER_H
