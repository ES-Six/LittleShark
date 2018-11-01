#include <iostream>

#include "packet_wrapper.h"

namespace MyLibPCAP
{
    MyLibPCAP::PacketWrapper::PacketWrapper() {

    }

    MyLibPCAP::PacketWrapper::~PacketWrapper() {

        delete this->packetHeader;
        delete[] this->packetContent;
    }

    void MyLibPCAP::PacketWrapper::setPacketHeader(pcap_pkthdr *packetHeader) {
        this->packetHeader = packetHeader;
    }

    void MyLibPCAP::PacketWrapper::setPacketContent(unsigned char *packetContent) {
        this->packetContent = packetContent;
    }

    pcap_pkthdr *MyLibPCAP::PacketWrapper::getPacketHeader() const {
        return this->packetHeader;
    }

    unsigned char *MyLibPCAP::PacketWrapper::getPacketContent() const {
        return this->packetContent;
    }
}
