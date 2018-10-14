#ifndef MY_LIBPCAP_PCAPFILEWRITER_H
#define MY_LIBPCAP_PCAPFILEWRITER_H

#include <string>
#include <fstream>

#include "pcap_file_headers.h"

namespace MyLibPCAP
{
    class PCAPFileWriter
    {
    public:
        explicit PCAPFileWriter(const std::string &, uint32_t);
        ~PCAPFileWriter();
        bool writePacketToFile(char *, uint32_t, uint32_t, uint32_t);
    private:
        struct pcap_file_header pcap_header;
        std::ofstream *of_stream = nullptr;
        uint32_t snaplen = 0x00040000;
    };
}

#endif //MY_LIBPCAP_PCAPFILEWRITER_H
