#include <iostream>

#include "../header/packet_wrapper.h"

namespace MyLibPCAP
{
    MyLibPCAP::PacketWrapper::PacketWrapper() {
        std::cout << "PacketWrapper built" << std::endl;
    }

    MyLibPCAP::PacketWrapper::~PacketWrapper() {
        std::cout << "PacketWrapper destroyed" << std::endl;
        delete this->packetHeader;
        delete[] this->packetContent;
    }

    void MyLibPCAP::PacketWrapper::setPacketHeader(pcap_pkthdr *packetHeader) {
        this->packetHeader = packetHeader;
    }

    void MyLibPCAP::PacketWrapper::setPacketContent(char *packetContent) {
        this->packetContent = packetContent;
    }

    pcap_pkthdr *MyLibPCAP::PacketWrapper::getPacketHeader() const {
        return this->packetHeader;
    }

    char *MyLibPCAP::PacketWrapper::getPacketContent() const {
        return this->packetContent;
    }
}