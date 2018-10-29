#ifndef MY_LIBPCAP_LIBRARY_H
#define MY_LIBPCAP_LIBRARY_H

#include <string>
#include <fstream>

#include "pcap_file_headers.h"
#include "packet_wrapper.h"

namespace MyLibPCAP
{
    // Unknown means unsupported endianess or bad file
    // Identical same endianness, no swap needed
    // Swapped not the same endianess, need to swap values
    enum pcap_endianess {
        IS_UNKNOWN,
        IS_IDENTICAL,
        IS_SWAPPED,
    };

    class PCAPFileReader
    {
    public:
        explicit PCAPFileReader(const std::string &);
        ~PCAPFileReader();
        pcap_endianess getFileEndianess();
        bool hasNextPacket();
        PacketWrapper *getNextPacket() const;
        pcap_file_header *getPCAPFileHeader();
    private:
        struct pcap_file_header pcap_header;
        std::ifstream *in_stream = nullptr;
        PacketWrapper *nextPacket = nullptr;
    };
}

#endif