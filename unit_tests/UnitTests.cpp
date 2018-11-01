#include <QtTest/QtTest>
#include "../PacketGenerator.h"
#include "../PCAPFileReader.h"
#include "../CNetworkSniffer.h"

class UnitTests: public QObject
{
    Q_OBJECT
private slots:
    void testICMPForging();
    void testTCPForging();
    void testUDPForging();
    void testBadConfigForging();
    void testNoTargetForging();
    void readAFile();
    void testTCPPacketAnalyser();
    void testUDPPacketAnalyser();
    void testICMPPacketAnalyser();
    void nulltrPacketAnalyserTest();
    void advancedAnalyserTests();
};

void UnitTests::testICMPForging()
{
    PacketGenerator generator;
    generator.setTarget("FF:FF:FF:FF:FF:FF", "FF:FF:FF:FF:FF:FF", "127.0.0.1", "127.0.0.1", 4242, 4243);
    std::string content = "PACKET CONTENT";
    const unsigned char *icmp_packet = generator.createPacket(reinterpret_cast<const unsigned char *>(content.c_str()), content.length(), PacketGenerator::WITH_IPV4 | PacketGenerator::WITH_ICMP);
    QVERIFY2(icmp_packet != nullptr, "TESTNG ERROR : ICMP Packet forging broken");
}

void UnitTests::testTCPForging()
{
    PacketGenerator generator;
    generator.setTarget("FF:FF:FF:FF:FF:FF", "FF:FF:FF:FF:FF:FF", "127.0.0.1", "127.0.0.1", 4242, 4243);
    std::string content = "PACKET CONTENT";
    const unsigned char *tcp_packet = generator.createPacket(reinterpret_cast<const unsigned char *>(content.c_str()), content.length(), PacketGenerator::WITH_IPV4 | PacketGenerator::WITH_TCP);
    QVERIFY2(tcp_packet != nullptr, "TESTNG ERROR : TCP Packet forging broken");
}

void UnitTests::testUDPForging()
{
    PacketGenerator generator;
    generator.setTarget("FF:FF:FF:FF:FF:FF", "FF:FF:FF:FF:FF:FF", "127.0.0.1", "127.0.0.1", 4242, 4243);
    std::string content = "PACKET CONTENT";
    const unsigned char *udp_packet = generator.createPacket(reinterpret_cast<const unsigned char *>(content.c_str()), content.length(), PacketGenerator::WITH_IPV4 | PacketGenerator::WITH_UDP);
    QVERIFY2(udp_packet != nullptr, "TESTNG ERROR : UDP Packet forging broken");
}

void UnitTests::testBadConfigForging()
{
    PacketGenerator generator;
    generator.setTarget("FF:FF:FF:FF:FF:FF", "FF:FF:FF:FF:FF:FF", "127.0.0.1", "127.0.0.1", 4242, 4243);
    std::string content = "PACKET CONTENT";
    const unsigned char *udp_packet = generator.createPacket(reinterpret_cast<const unsigned char *>(content.c_str()), content.length(), 0);
    QVERIFY2(udp_packet == nullptr, "TESTNG ERROR : Packet forging no proto error handling broken");
}

void UnitTests::testNoTargetForging()
{
    PacketGenerator generator;
    std::string content = "PACKET CONTENT";
    const unsigned char *udp_packet = generator.createPacket(reinterpret_cast<const unsigned char *>(content.c_str()), content.length(), 0);
    QVERIFY2(udp_packet == nullptr, "TESTNG ERROR : Packet forging no target error handling broken");
}

void UnitTests::readAFile()
{
    MyLibPCAP::PCAPFileReader test = MyLibPCAP::PCAPFileReader("test.pcap");

    unsigned int packet_count = 0;
    while (test.hasNextPacket()) {
        MyLibPCAP::PacketWrapper *packetWrapper = test.getNextPacket();
        QVERIFY2(packetWrapper != nullptr, "PCAPReder broken: nullptr received instead of PacketWraper");
        if (packetWrapper->getPacketHeader()->caplen == packetWrapper->getPacketHeader()->len) {
            // OK
        } else if (packetWrapper->getPacketHeader()->caplen < packetWrapper->getPacketHeader()->len) {
            // OK
        } else{
            // Very bad
            QVERIFY2(false, "PCAP File reading error : impossible values");
            return;
        }
        delete packetWrapper;
        packet_count ++;
    }
    QVERIFY2(packet_count != 0, "PCAP File reading error : no packets was read");
}

void UnitTests::testTCPPacketAnalyser()
{
    PacketGenerator generator;
    generator.setTarget("FF:FF:FF:FF:FF:FF", "FF:FF:FF:FF:FF:FF", "127.0.0.1", "127.0.0.1", 8080, 80);
    std::string content = "PACKET CONTENT";
    unsigned char *tcp_packet = generator.createPacket(reinterpret_cast<const unsigned char *>(content.c_str()), content.length(), PacketGenerator::WITH_IPV4 | PacketGenerator::WITH_TCP);
    QVERIFY2(tcp_packet != nullptr, "Create packet error, packet generator broker");
    C_NetworkSniffer sniffer;
    CEthenetFrame *frame = sniffer.parse(tcp_packet, generator.getCreatedPacketSize());
    QVERIFY2(frame != nullptr, "Network sniffer broken: nullptr received");
    if (frame->isIPv4Protocol()) {
        if (frame->getCPacket() != nullptr && frame->getCPacket()->isTCPProtocol()) {
            // OK
        } else {
            QVERIFY2(false, "Network sniffer broker, no TCP header found");
        }
    } else {
        QVERIFY2(false, "Network sniffer broker, bad Protocol detected");
    }
}

void UnitTests::testUDPPacketAnalyser()
{
    PacketGenerator generator;
    generator.setTarget("FF:FF:FF:FF:FF:FF", "FF:FF:FF:FF:FF:FF", "127.0.0.1", "127.0.0.1", 8080, 80);
    std::string content = "PACKET CONTENT";
    unsigned char *udp_packet = generator.createPacket(reinterpret_cast<const unsigned char *>(content.c_str()), content.length(), PacketGenerator::WITH_IPV4 | PacketGenerator::WITH_UDP);
    QVERIFY2(udp_packet != nullptr, "Create packet error, packet generator broker");
    C_NetworkSniffer sniffer;
    CEthenetFrame *frame = sniffer.parse(udp_packet, generator.getCreatedPacketSize());
    QVERIFY2(frame != nullptr, "Network sniffer broken: nullptr received");
    if (frame->isIPv4Protocol()) {
        if (frame->getCPacket() != nullptr && frame->getCPacket()->isUDPProtocol()) {
            // OK
        } else {
            QVERIFY2(false, "Network sniffer broker, no TCP header found");
        }
    } else {
        QVERIFY2(false, "Network sniffer broker, bad Protocol detected");
    }
}

void UnitTests::testICMPPacketAnalyser()
{
    PacketGenerator generator;
    generator.setTarget("FF:FF:FF:FF:FF:FF", "FF:FF:FF:FF:FF:FF", "127.0.0.1", "127.0.0.1", 8080, 80);
    std::string content = "PACKET CONTENT";
    unsigned char *icmpv4_packet = generator.createPacket(reinterpret_cast<const unsigned char *>(content.c_str()), content.length(), PacketGenerator::WITH_IPV4 | PacketGenerator::WITH_ICMP);
    QVERIFY2(icmpv4_packet != nullptr, "Create packet error, packet generator broker");
    C_NetworkSniffer sniffer;
    CEthenetFrame *frame = sniffer.parse(icmpv4_packet, generator.getCreatedPacketSize());
    QVERIFY2(frame != nullptr, "Network sniffer broken: nullptr received");
    if (frame->isIPv4Protocol()) {
        if (frame->getCPacket() != nullptr && frame->getCPacket()->isICMPv4Protocol()) {
            // OK
        } else {
            QVERIFY2(false, "Network sniffer broker, no TCP header found");
        }
    } else {
        QVERIFY2(false, "Network sniffer broker, bad Protocol detected");
    }
}


void UnitTests::nulltrPacketAnalyserTest()
{
    C_NetworkSniffer sniffer;
    CEthenetFrame *frame = sniffer.parse(nullptr, 4242);
    QVERIFY2(frame == nullptr, "Network sniffer error handling broken : no nullptr received");
}

void UnitTests::advancedAnalyserTests()
{
    unsigned int ipv4 = 0;
    unsigned int ipv6 = 0;
    unsigned int arp = 0;
    unsigned int tcp = 0;
    unsigned int udp = 0;
    unsigned int dns = 0;
    unsigned int unknown = 0;

    const unsigned int expected_ipv4 = 7;
    const unsigned int expected_ipv6 = 13;
    const unsigned int expected_arp = 7;
    const unsigned int expected_tcp = 3;
    const unsigned int expected_udp = 4;
    const unsigned int expected_dns = 4;
    const unsigned int expected_unknown = 2;

    MyLibPCAP::PCAPFileReader test = MyLibPCAP::PCAPFileReader("test.pcap");

    unsigned int packet_count = 0;
    while (test.hasNextPacket()) {
        MyLibPCAP::PacketWrapper *packetWrapper = test.getNextPacket();
        QVERIFY2(packetWrapper != nullptr, "PCAPReder broken: nullptr received instead of PacketWraper");
        if (packetWrapper->getPacketHeader()->caplen == packetWrapper->getPacketHeader()->len) {
            C_NetworkSniffer sniffer;
            CEthenetFrame *frame = sniffer.parse(packetWrapper->getPacketContent(), packetWrapper->getPacketHeader()->caplen);
            if (frame != nullptr && frame->isIPv4Protocol()) {
                ipv4 ++;
                if (frame->getCPacket() != nullptr && frame->getCPacket()->isTCPProtocol()) {
                    tcp ++;
                    if (frame->getCPacket()->getDNSParser().isValiddDNSPacket()) {
                        dns ++;
                    }
                } else if (frame->getCPacket() != nullptr && frame->getCPacket()->isUDPProtocol()) {
                    udp ++;
                    if (frame->getCPacket()->getDNSParser().isValiddDNSPacket()) {
                        dns ++;
                    }
                }
            } else if (frame != nullptr && frame->isIPv6Protocol()) {
                ipv6 ++;
            } else if (frame != nullptr && frame->isARPProtocol()) {
                arp ++;
            } else if (frame != nullptr) {
                unknown ++;
            }
        } else if (packetWrapper->getPacketHeader()->caplen < packetWrapper->getPacketHeader()->len) {
            QVERIFY2(false, "Bad unit test: partial packet test case should not happend in this test");
        } else {
            // Very bad
            QVERIFY2(false, "PCAP File reading error : impossible values");
            return;
        }
        delete packetWrapper;
        packet_count ++;
    }

    QVERIFY2(packet_count != 0, "PCAP File reading error : no packets was read");
    QVERIFY2(ipv4 == expected_ipv4, "Error IPv4 packet stats are different from expected packet stats");
    QVERIFY2(ipv6 == expected_ipv6, "Error IPv6 packet stats are different from expected packet stats");
    QVERIFY2(tcp == expected_tcp, "Error TCP packet stats are different from expected packet stats");
    QVERIFY2(udp == expected_udp, "Error IPv4 packet stats are different from expected packet stats");
    QVERIFY2(dns == expected_dns, "Error DNS packet stats are different from expected packet stats");
    QVERIFY2(arp == expected_arp, "Error ARP packet stats are different from expected packet stats");
    QVERIFY2(unknown == expected_unknown, "Error Unknown packet stats are different from expected packet stats");
}

QTEST_MAIN(UnitTests)
#include "UnitTests.moc"
