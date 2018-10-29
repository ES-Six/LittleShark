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
    bool isDNSAnswer() const;
    bool isDNSQuery() const;

    const std::string &getDomainName() const;
    uint16_t getQueryType() const;
    uint16_t getQueryCount() const;
    uint16_t getAnswerCount() const;
    const std::vector<std::string> &getRecords() const;

    static std::string dnsQueryTypeToStr(uint16_t qtype);
private:
    // Fonctionalitées internes
    unsigned char *buffer = nullptr;
    u_char *readDNSMXLabel(u_char **, u_char *, size_t, const u_char *, const u_char *, bool &);
    u_char *readDNSLabel(u_char **, u_char *, size_t, const u_char *, const u_char *);
    void displayDNSEntry(uint16_t, uint16_t, u_char *, u_char *, u_char *, u_char *);
    unsigned char *skipRDATA(unsigned char *);
    bool isLabelValid(const u_char *label);

    // Fonctionalités externalisés avec des getters
    bool isValidDNSHeader = false;
    bool isQuery = false;
    bool isAnswer = false;

    std::string domainLabel;
    uint16_t queryType = 0;
    uint16_t queryCount = 0;
    uint16_t answerCount = 0;
    std::vector<std::string> m_vDNSRecords;
    struct dnshdr *dnsHeader = nullptr;
};


#endif //LITTLE_SHARK_DNSPARSER_H
