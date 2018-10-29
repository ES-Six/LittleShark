//
// Created by brendan on 21/10/18.
//

#include "DNSParser.h"

#include <cstring>

DNSParser::DNSParser() {
    this->buffer = new unsigned char[65536];
}

DNSParser::~DNSParser() {
    delete[] this->buffer;
}

u_char *DNSParser::readDNSMXLabel(u_char **label, u_char *dest,
                                size_t dest_size,
                                const u_char *payload,
                                const u_char *end, bool &mustByLabelCompleted)
{
    u_char *tmp, *dst = dest;

    if (!label || !*label || !dest) {
        if (dest) *dest = '\0';
        return dest;
    }

    mustByLabelCompleted = false;

    *dest = '\0';
    while (*label < end && **label) {
        if (**label & 0xc0) { /* Pointer */
            tmp = (u_char *)payload;
            tmp += ntohs(*(uint16_t *)(*label)) & 0x3fff;
            while (tmp < end && *tmp) {
                if (dst + *tmp >= dest + dest_size) {
                    if (dest) *dest = '\0';
                    return dest;
                }
                memcpy(dst, tmp+1, *tmp);
                dst += *tmp; tmp += *tmp + 1;
                if (dst > dest + dest_size) {
                    if (dest) *dest = '\0';
                    return dest;
                }
                *dst = '.';
                dst++;

                if (*tmp == 192) {
                    mustByLabelCompleted = true;
                    break;
                }
            }
            *label += 2;
        } else { /* Label */
            if ((*label + **label) >= end) {
                if (dest) *dest = '\0';
                return dest;
            }
            if (**label + dst >= dest + dest_size) {
                if (dest) *dest = '\0';
                return dest;
            }
            memcpy(dst, *label + 1, **label);
            dst += **label;
            if (dst > dest + dest_size) {
                if (dest) *dest = '\0';
                return dest;
            }
            *label += **label + 1;
            *dst = '.'; dst++;
        }
    }

    *(--dst) = '\0';
    return dest;
}

u_char *DNSParser::readDNSLabel(u_char **label, u_char *dest,
                                size_t dest_size,
                                const u_char *payload,
                                const u_char *end)
{
    u_char *tmp, *dst = dest;

    if (!label || !*label || !dest) {
        if (dest) *dest = '\0';
        return dest;
    }

    *dest = '\0';
    while (*label < end && **label) {
        if (**label & 0xc0) { /* Pointer */
            tmp = (u_char *)payload;
            tmp += ntohs(*(uint16_t *)(*label)) & 0x3fff;
            while (tmp < end && *tmp) {
                if (dst + *tmp >= dest + dest_size) {
                    if (dest) *dest = '\0';
                    return dest;
                }
                memcpy(dst, tmp+1, *tmp);
                dst += *tmp; tmp += *tmp + 1;
                if (dst > dest + dest_size) {
                    if (dest) *dest = '\0';
                    return dest;
                }
                *dst = '.'; dst++;
            };
            *label += 2;
        } else { /* Label */
            if ((*label + **label) >= end) {
                if (dest) *dest = '\0';
                return dest;
            }
            if (**label + dst >= dest + dest_size) {
                if (dest) *dest = '\0';
                return dest;
            }
            memcpy(dst, *label + 1, **label);
            dst += **label;
            if (dst > dest + dest_size) {
                if (dest) *dest = '\0';
                return dest;
            }
            *label += **label + 1;
            *dst = '.'; dst++;
        }
    }

    *(--dst) = '\0';
    return dest;
}

unsigned char *DNSParser::skipRDATA(unsigned char *label) {
    u_char *cursor;

    if (!label) {
        return nullptr;
    }
    if (*label & 0xc0) {
        return label + 2;
    }

    cursor = label;
    while (*label) {
        cursor += *label + 1;
        label = cursor;
    }
    return label + 1;
}

std::string DNSParser::dnsQueryTypeToStr(uint16_t qtype) {
    //On gère pas tout, juste le strict minimum pour afficher que c'est une entrée DNS
    switch (qtype) {
        case 1: /* A */
            return std::string("A");
        case 2:  /* NS */
            return std::string("NS");
        case 5:  /* CNAME */
            return std::string("CNAME");
        case 12: /* PTR */
            return std::string("PTR");
        case 15: /* MX (16-bit priority / label) */
            return std::string("MX");
        case 16: /* TXT (1 byte text length / text) */
            return std::string("TXT");
        case 28: /* AAAA */
            return std::string("AAAA");
        default:
            return std::string("UNKNOWN");
    }
}

void DNSParser::displayDNSEntry(uint16_t len, uint16_t qtype, u_char *tmp, u_char *start, u_char *end, u_char *label) {
    std::string dnsQuery;
    const char *data = nullptr;
    int i = 0;
    bool mustByLabelCompleted = false;
    u_char buf[8192];
    char dbuf[8192];
    std::string postLabeled;

    /* Get data len */
    len = ntohs(*(uint16_t *)tmp);
    tmp += 2;

    switch (qtype) {
        case 1:
            data = inet_ntop(AF_INET, tmp, dbuf, 8192);
            break;
        case 2:
        case 5:
        case 12:
            data = (char *)readDNSMXLabel(
                    &tmp, (u_char *)dbuf, 8192,
                    start, tmp + len, mustByLabelCompleted
            );
            break;
        case 15: {
            i = snprintf(dbuf, 7, "%u ", ntohs(*(uint16_t *) tmp));
            tmp += 2;

            u_char *old = tmp;

            data = (char *) readDNSMXLabel(
                    &tmp, (u_char *) (dbuf + i), 8192 - i,
                    start, tmp + len - 2, mustByLabelCompleted
            );
            if (mustByLabelCompleted)
                postLabeled = std::string(dbuf) + '.' + std::string((char *)label);
            else
                postLabeled = std::string(dbuf);
            data = postLabeled.c_str();
            break;
        }
        case 16:
            if (*tmp <= len && tmp + len < end) {
                memcpy(dbuf, tmp+1, *tmp);
                dbuf[*tmp+1] = '\0';
            } else *dbuf = '\0';
            data = dbuf;
            break;
        case 28:
            data = inet_ntop(AF_INET6, tmp, dbuf, 8192);
            break;
        default:
            *dbuf = '\0';
            data = dbuf;
    }

    this->m_vDNSRecords.emplace_back(data);
}

bool DNSParser::isLabelValid(const u_char *label) {
    int label_len = 0;
    const std::string allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.";
    while (*label != 0 && label_len < 63) {
        if (allowed_chars.find(*label) == std::string::npos) {
            return false;
        }
        label ++;
        label_len ++;
    }
    if (label_len == 0)
        return false;
    else if (label_len > 63)
        return false;

    return true;
}

void DNSParser::parseData(unsigned char * old_buffer, uint16_t max_length) {
    //L'enfer sur terre
    memcpy(this->buffer, old_buffer, static_cast<int>(max_length));
    unsigned char *start = buffer;
    unsigned char *end = buffer + max_length;
    unsigned char *cursor = buffer;
    u_char *label = nullptr;
    u_char buf[8192];
    char dbuf[8192];
    u_char *tmp = nullptr;
    const char *data = nullptr;
    uint16_t len = 0;
    uint16_t qtype = 0;
    int i = 0;

    if (max_length < sizeof(struct dnshdr)) {
        //Skip if not minimum size of a dns query
        return;
    }

    /* fill struct with values in correct endianess */
    this->dnsHeader = reinterpret_cast<struct dnshdr *>(start);
    this->dnsHeader->id      = ntohs(this->dnsHeader->id);
    this->dnsHeader->flags   = ntohs(this->dnsHeader->flags);
    this->dnsHeader->qdcount = ntohs(this->dnsHeader->qdcount);
    this->dnsHeader->ancount = ntohs(this->dnsHeader->ancount);
    this->dnsHeader->nscount = ntohs(this->dnsHeader->nscount);
    this->dnsHeader->arcount = ntohs(this->dnsHeader->arcount);

    /* Skip every empty / incorrect packets */
    if (!dnsHeader->qdcount) {
        return;
    }

    this->queryCount = dnsHeader->qdcount;
    this->answerCount = dnsHeader->ancount;

    /* Parse the Query section */
    tmp = (u_char *)(start + 12);
    for (i=0;i<dnsHeader->qdcount;i++) {
        if (!qtype) {
            label = readDNSLabel(&tmp, buf, 8192, start, end);
            tmp++;
            qtype = ntohs(*(uint16_t *)tmp);
            if ((dnsHeader->flags & 0x8000) != 0x8000) {
                this->domainLabel = reinterpret_cast<const char *>(label);
                if (!this->isLabelValid(reinterpret_cast<const u_char *>(label))) {
                    return;
                }
                this->queryType = qtype;
                this->isQuery = true;
                this->isValidDNSHeader = true;
                return;
            }
        } else {
            if (*tmp & 0xc0) tmp += 2;
            else tmp = skipRDATA(tmp);
        }

        /* Skip header */
        tmp += 4;
        if (tmp >= end) {
            return;
        }
    }

    this->queryType = qtype;
    this->domainLabel = reinterpret_cast<const char *>(label);

    /* Parse the Answer section */
    if (!qtype) {
        return;
    }
    for (i = 0; i < dnsHeader->ancount; i ++) {
        tmp = skipRDATA(tmp);
        if (tmp + 10 > end) {
            return;
        }

        /* Check type, an skip header fields */
        len = ntohs(*(uint16_t *)tmp); tmp += 8;
        if (len == qtype) {
            displayDNSEntry(len, qtype, tmp, start, end, label);
        }

        /* Go to next answer */
        tmp += ntohs(*(uint16_t *)tmp) + 2;
        if (tmp > end) {
            return;
        }
    }

    if (!this->isLabelValid(reinterpret_cast<const u_char *>(this->domainLabel.c_str()))) {
        return;
    }

    // Indicate buffer contain valid DNS headers
    this->isAnswer = true;
    this->isValidDNSHeader = true;
}

bool DNSParser::isValiddDNSPacket() const {
    return this->isValidDNSHeader;
}

bool DNSParser::isDNSQuery() const {
    return this->isQuery;
}

bool DNSParser::isDNSAnswer() const {
    return this->isAnswer;
}

const std::string &DNSParser::getDomainName() const {
    return this->domainLabel;
}

uint16_t DNSParser::getQueryType() const {
    return this->queryType;
}

uint16_t DNSParser::getQueryCount() const {
    return this->queryCount;
}

uint16_t DNSParser::getAnswerCount() const {
    return this->answerCount;
}

const std::vector<std::string> &DNSParser::getRecords() const {
    return this->m_vDNSRecords;
}
