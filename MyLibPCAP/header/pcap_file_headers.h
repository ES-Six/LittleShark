//
// Created by brendan on 13/10/18.
//

#ifndef MY_LIBPCAP_PCAP_FILE_HEADERS_H
#define MY_LIBPCAP_PCAP_FILE_HEADERS_H

#include <cstdint>
#include <sys/time.h>

namespace MyLibPCAP {
    struct pcap_file_header {
        uint32_t magic;
        uint16_t version_major;
        uint16_t version_minor;
        int32_t thiszone;    /* gmt to local correction */
        uint32_t sigfigs;    /* accuracy of timestamps */
        uint32_t snaplen;    /* max length of saved portion of each pkt */
        uint32_t linktype;   /* data link type (LINKTYPE_*) */
    };

    struct pcap_pkthdr {
        uint32_t ts_sec;     /* timestamp seconds */
        uint32_t ts_usec;    /* timestamp microseconds */
        uint32_t caplen;     /* length of the packet portion present in file */
        uint32_t len;        /* real length this packet (off wire) */
    };
}

#endif //MY_LIBPCAP_PCAP_FILE_HEADERS_H
