#include "PCAPFileWriter.h"

#include <iostream>


namespace MyLibPCAP {
    MyLibPCAP::PCAPFileWriter::PCAPFileWriter(const std::string &file_path, uint32_t linkType) {
        std::cout << "Création du du fichier : " << file_path << std::endl;
        of_stream = new std::ofstream(file_path, std::ofstream::out | std::ofstream::trunc | std::ofstream::binary);

        if (!of_stream->is_open()) {
            std::cout << "Echec de la créaction du fichier: " << file_path << std::endl;
            return;
        }

        MyLibPCAP::pcap_file_header header;
        header.magic = 0xA1B2C3D4;
        header.version_major = 2;
        header.version_minor = 4;
        header.thiszone = 0;
        header.sigfigs = 0;
        header.snaplen = this->snaplen;
        header.linktype = linkType;
        of_stream->write((char *) &header, sizeof(header));

        std::cout << "Writed file header bytes : " << of_stream->tellp() << std::endl;
    }

    MyLibPCAP::PCAPFileWriter::~PCAPFileWriter() {
        std::cout << "Nuke everything" << std::endl;
        if (of_stream->is_open()) {
            of_stream->close();
            delete of_stream;
        }
    }

    bool MyLibPCAP::PCAPFileWriter::writePacketToFile(char *packetcontent, uint32_t length, uint32_t ts_sec,
                                                 uint32_t ts_usec) {
        if (!of_stream->is_open()) {
            std::cout << "Error: cannot write to file, stream not open" << std::endl;
            return false;
        }

        uint32_t total_length = length;
        uint32_t bytes_to_write = length;

        while (bytes_to_write) {
            uint32_t chunk_bytes_to_write = 0;
            if (bytes_to_write < this->snaplen) {
                chunk_bytes_to_write = bytes_to_write;
            } else {
                chunk_bytes_to_write = bytes_to_write - this->snaplen;
            }

            MyLibPCAP::pcap_pkthdr pktheader;
            pktheader.ts_sec = ts_sec;
            pktheader.ts_usec = ts_usec;
            pktheader.len = total_length;
            pktheader.caplen = chunk_bytes_to_write;

            of_stream->write((char *) &pktheader, sizeof(pktheader));
            std::cout << "Writed packet header bytes : " << of_stream->tellp() << std::endl;

            if (of_stream->fail()) {
                std::cout << "Failed to write header bytes " << std::endl;
                return false;
            }

            of_stream->write(packetcontent, chunk_bytes_to_write);
            std::cout << "Writed packet content bytes : " << of_stream->tellp() << std::endl;

            if (of_stream->fail()) {
                std::cout << "Failed to write header bytes " << std::endl;
                return false;
            }

            packetcontent += chunk_bytes_to_write;
            bytes_to_write -= chunk_bytes_to_write;
        }

        return true;
    }
}
