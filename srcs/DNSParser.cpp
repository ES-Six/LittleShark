//
// Created by brendan on 21/10/18.
//

#include "../headers/DNSParser.h"

#include <cstring>

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
        case 17: /* AAAA */
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
    len = ntohs(*(uint16_t *)tmp); tmp += 2;
    if (qtype == 28) qtype = 17; /* for AAAA compatibility */

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
        case 17:
            data = inet_ntop(AF_INET6, tmp, dbuf, 8192);
            break;
        default:
            *dbuf = '\0';
            data = dbuf;
    }
    dnsQuery += dnsQueryTypeToStr(qtype);
    dnsQuery += ": ";
    dnsQuery += reinterpret_cast<char *>(label);
    dnsQuery += " => ";
    dnsQuery += data;

    std::cout << dnsQuery << std::endl;
}

void DNSParser::parseData(unsigned char *buffer, uint16_t max_length) {
    //L'enfer sur terre
    unsigned char *start = buffer;
    unsigned char *end = buffer + max_length;
    unsigned char *cursor = buffer;
    u_char *label = nullptr;
    u_char buf[8192];
    char dbuf[8192];
    struct dnshdr *dnsh = nullptr;
    u_char *tmp = nullptr;
    const char *data = nullptr;
    uint16_t len = 0;
    uint16_t qtype = 0;
    int i = 0;

    if (max_length < sizeof(struct dnshdr)) {
        //Skip if not minimum size of a dns query
        return;
    }

    auto dnsHeader = reinterpret_cast<struct dnshdr *>(buffer);

    /* fill struct with values in correct endianess */
    dnsh = (struct dnshdr *)(start);
    dnsh->id      = ntohs(dnsh->id);
    dnsh->flags   = ntohs(dnsh->flags);
    dnsh->qdcount = ntohs(dnsh->qdcount);
    dnsh->ancount = ntohs(dnsh->ancount);
    dnsh->nscount = ntohs(dnsh->nscount);
    dnsh->arcount = ntohs(dnsh->arcount);

    /* Disregard malformed packets */
    if (!dnsh->ancount || !dnsh->qdcount) {
        return;
    }

    std::cout << "The response contains : " <<  dnsHeader->qdcount << " questions." << std::endl;
    std::cout << "The response contains : " << dnsHeader->ancount << " answers." << std::endl;
    std::cout << "The response contains : " << dnsHeader->nscount << " authoritative Servers." << std::endl;
    std::cout << "The response contains : " << dnsHeader->arcount << " additional records." << std::endl;

    /* Parse the Query section */
    tmp = (u_char *)(start + 12);
    for (i=0;i<dnsh->qdcount;i++) {
        if (!qtype) {
            label = readDNSLabel(&tmp, buf, 8192, start, end);
            tmp++;
            qtype = ntohs(*(uint16_t *)tmp);
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

    /* Parse the Answer section */
    if (!qtype) {
        return;
    }
    for (i=0;i<dnsh->ancount;i++) {
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

    // Indicate buffer contain valid DNS headers
    this->isValidDNSHeader = true;
}

bool DNSParser::isValiddDNSPacket() const {
    return this->isValidDNSHeader;
}