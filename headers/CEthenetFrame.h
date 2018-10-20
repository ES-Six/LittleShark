#ifndef LITTLE_SHARK_CETHENETFRAME_H
#define LITTLE_SHARK_CETHENETFRAME_H

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "CPacket.h"

class CEthenetFrame {
public:
    CEthenetFrame() = default;
    ~CEthenetFrame();

    void parseEthernetFrame(unsigned char *);

    bool isIPv4Protocol() const;
    bool isIPv6Protocol() const;
    bool isARPProtocol() const;

    void setIPv4Header(struct iphdr *);
    void setIPv6Header(struct ipv6hdr *);
    void setARPHeader(struct arphdr *);

    struct iphdr *getIPv4Header() const;
    struct ipv6hdr *getIPv6Header() const;
    struct arphdr *getARPHeader() const;
    struct ethhdr *getEthernetFrame() const;
    CPacket *getCPacket() const;
private:
    struct ethhdr *m_pEthernetFrame = nullptr;
    struct iphdr *m_pIPv4hdr = nullptr;
    struct ipv6hdr *m_pIPv6hdr = nullptr;
    struct arphdr *m_pARPhdr = nullptr;
    unsigned char *m_pBuffer = nullptr;
    CPacket *m_pCPacket = nullptr;
};


#endif //LITTLE_SHARK_CETHENETFRAME_H
