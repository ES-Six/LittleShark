//
// Created by brendan on 21/10/18.
//

#ifndef LITTLE_SHARK_DNSPARSER_H
#define LITTLE_SHARK_DNSPARSER_H

#include <cstdint>
#include <iostream>
#include <string>
#include <arpa/inet.h>
#include <vector>

/**
 * DNS header
 */

struct dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

class DNSParser {
public:
    DNSParser();
    ~DNSParser();

    void parseData(unsigned char *, uint16_t);
    bool isValiddDNSPacket() const;
private:
    unsigned char *buffer = nullptr;
    u_char *readDNSMXLabel(u_char **, u_char *, size_t, const u_char *, const u_char *, bool &);
    u_char *readDNSLabel(u_char **, u_char *, size_t, const u_char *, const u_char *);
    void displayDNSEntry(uint16_t, uint16_t, u_char *, u_char *, u_char *, u_char *);
    unsigned char *skipRDATA(unsigned char *);
    std::string dnsQueryTypeToStr(uint16_t qtype);

    bool isValidDNSHeader = false;
    std::string dnsQuery;
};


#endif //LITTLE_SHARK_DNSPARSER_H
