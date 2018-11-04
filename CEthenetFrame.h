#ifndef LITTLE_SHARK_CETHENETFRAME_H
#define LITTLE_SHARK_CETHENETFRAME_H

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>
#include <netinet/ip6.h>
#include "CPacket.h"

class CEthenetFrame {
public:
    CEthenetFrame() = default;
    ~CEthenetFrame();

    void parseEthernetFrame(unsigned char *, ssize_t);

    bool isIPv4Protocol() const;
    bool isIPv6Protocol() const;
    bool isARPProtocol() const;

    void setIPv4Header(struct iphdr *);
    void setIPv6Header(struct ipv6hdr *);
    void setARPHeader(struct arphdr *);
    void setTotalLen(ssize_t);

    struct iphdr *getIPv4Header() const;
    struct ipv6hdr *getIPv6Header() const;
    struct arphdr *getARPHeader() const;
    struct ethhdr *getEthernetFrame() const;
    CPacket *getCPacket() const;
    ssize_t getTotalLen() const;
private:
    struct ethhdr *m_pEthernetFrame = nullptr;
    struct iphdr *m_pIPv4hdr = nullptr;
    struct ipv6hdr *m_pIPv6hdr = nullptr;
    struct arphdr *m_pARPhdr = nullptr;
    unsigned char *m_pBuffer = nullptr;
    CPacket *m_pCPacket = nullptr;
    ssize_t total_len = 0;
    // const unsigned int MAX_PACKET_LEN = 65536;
};


#endif //LITTLE_SHARK_CETHENETFRAME_H
