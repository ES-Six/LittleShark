#include "../header/PCAPFileReader.h"

#include <iostream>


namespace MyLibPCAP
{
    MyLibPCAP::PCAPFileReader::PCAPFileReader(const std::string &file_path)
    {
        std::cout << "Ouverture du fichier : " << file_path << std::endl;
        in_stream = new std::ifstream(file_path, std::ifstream::binary);

        if (!in_stream->is_open()) {
            std::cout << "Echec de l'ouverture du fichier: " << file_path << std::endl;
            return;
        }
        in_stream->read((char *)&this->pcap_header, sizeof(MyLibPCAP::pcap_file_header));

        std::cout << "Taille du header : " << sizeof(MyLibPCAP::pcap_file_header) << " octets" << std::endl;
        std::cout << "Taille nombre d'octets lu : " << in_stream->gcount() << " octets" << std::endl;

        if (in_stream->gcount() < sizeof(MyLibPCAP::pcap_file_header)) {
            std::cout << "Error : truncated file" << std::endl;
            return;
        }
    }

    MyLibPCAP::PCAPFileReader::~PCAPFileReader() {
        std::cout << "Nuke everything" << std::endl;
        if (in_stream->is_open()) {
            in_stream->close();
            delete in_stream;
        }
    }

    MyLibPCAP::pcap_endianess MyLibPCAP::PCAPFileReader::getFileEndianess() {
        switch (this->pcap_header.magic) {
            case 0xA1B2C3D4:
                return MyLibPCAP::pcap_endianess::IS_IDENTICAL;
            case 0xD4C3B2A1:
                return MyLibPCAP::pcap_endianess::IS_SWAPPED;
            default:
                return MyLibPCAP::pcap_endianess::IS_UNKNOWN;
        }
    }

    MyLibPCAP::pcap_file_header *MyLibPCAP::PCAPFileReader::getPCAPFileHeader() {
        return &this->pcap_header;
    }

    bool MyLibPCAP::PCAPFileReader::hasNextPacket() {
        if (!in_stream->is_open()) {
            std::cout << "Cannot read anything, file is not opened" << std::endl;
            this->nextPacket = nullptr;
            return false;
        }

        auto pkthdr = new MyLibPCAP::pcap_pkthdr();

        in_stream->read((char *)pkthdr, sizeof(MyLibPCAP::pcap_pkthdr));

        std::cout << "Taille du header du paquet : " << sizeof(MyLibPCAP::pcap_pkthdr) << " octets" << std::endl;
        std::cout << "Taille nombre d'octets lu : " << in_stream->gcount() << " octets" << std::endl;

        if (in_stream->gcount() < sizeof(MyLibPCAP::pcap_pkthdr)) {
            if (in_stream->eof()) {
                std::cout << "Reached end of file" << std::endl;
            } else {
                std::cout << "Error : truncated file" << std::endl;
            }
            delete pkthdr;
            this->nextPacket = nullptr;
            return false;
        }
        if (this->pcap_header.snaplen < pkthdr->caplen) {
            std::cout << "Error: uncompatible file detected" << std::endl;
            delete pkthdr;
            this->nextPacket = nullptr;
            return false;
        }

        auto pktcontent = new char[pkthdr->caplen];

        in_stream->read(pktcontent, pkthdr->caplen);

        std::cout << "Taille du contenu du paquet : " << pkthdr->caplen << " octets" << std::endl;
        std::cout << "Taille nombre d'octets lu : " << in_stream->gcount() << " octets" << std::endl;

        if (in_stream->gcount() < pkthdr->caplen) {
            std::cout << "Error : truncated file" << std::endl;
            delete pkthdr;
            delete[] pktcontent;
            this->nextPacket = nullptr;
            return false;
        }

        this->nextPacket = new PacketWrapper();
        this->nextPacket->setPacketHeader(pkthdr);
        this->nextPacket->setPacketContent(reinterpret_cast<unsigned char *>(pktcontent));
        return this->nextPacket;
    }

    MyLibPCAP::PacketWrapper *MyLibPCAP::PCAPFileReader::getNextPacket() const {
        return this->nextPacket;
    }
}