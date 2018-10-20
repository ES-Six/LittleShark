#include "../headers/CEthenetFrame.h"

CEthenetFrame::~CEthenetFrame()
{
    delete m_pCPacket;
}

void CEthenetFrame::parseEthernetFrame(unsigned char *buffer) {
    this->m_pBuffer = buffer;
    this->m_pEthernetFrame = reinterpret_cast<struct ethhdr*>(buffer);

    buffer += sizeof(struct ethhdr);

    if (this->isARPProtocol()) {
        //Récupération du headerARP
        this->setARPHeader((struct arphdr*)(buffer));
    } else if (this->isIPv4Protocol()) {
        //Récupération du header IPv4
        this->setIPv4Header((struct iphdr*)(buffer));
        this->m_pCPacket = new CPacket();
        this->m_pCPacket->parseIPv4Protocol(buffer);
    } else if (this->isIPv6Protocol()) {
        //Récupération du header IPv6
        this->setIPv6Header((struct ipv6hdr*)(buffer));
    }
}

void CEthenetFrame::setIPv4Header(struct iphdr *header)
{
    this->m_pIPv4hdr = header;
}

void CEthenetFrame::setIPv6Header(struct ipv6hdr *header)
{
    this->m_pIPv6hdr = header;
}

void CEthenetFrame::setARPHeader(struct arphdr *header)
{
    this->m_pARPhdr = header;
}

struct iphdr *CEthenetFrame::getIPv4Header() const
{
    return this->m_pIPv4hdr;
}

struct ipv6hdr *CEthenetFrame::getIPv6Header() const
{
    return this->m_pIPv6hdr;
}

struct arphdr *CEthenetFrame::getARPHeader() const
{
    return this->m_pARPhdr;
}

CPacket *CEthenetFrame::getCPacket() const
{
    return this->m_pCPacket;
}

struct ethhdr *CEthenetFrame::getEthernetFrame() const
{
    return this->m_pEthernetFrame;
}

bool CEthenetFrame::isIPv4Protocol() const
{
    if (this->m_pEthernetFrame != nullptr) {
        return htons(this->m_pEthernetFrame->h_proto) == ETH_P_IP;
    } else {
        return false;
    }
}

bool CEthenetFrame::isIPv6Protocol() const
{
    if (this->m_pEthernetFrame != nullptr) {
        return htons(this->m_pEthernetFrame->h_proto) == ETH_P_IPV6;
    } else {
        return false;
    }
}

bool CEthenetFrame::isARPProtocol() const
{
    if (this->m_pEthernetFrame != nullptr) {
        return htons(this->m_pEthernetFrame->h_proto) == ETH_P_ARP;
    } else {
        return false;
    }
}