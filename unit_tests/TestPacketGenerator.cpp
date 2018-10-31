#include <QtTest/QtTest>
#include "../PacketGenerator.h"

class TestPacketGenerator: public QObject
{
    Q_OBJECT
private slots:
    void testICMPForging();
    void testTCPForging();
    void testUDPForging();
};

void TestPacketGenerator::testICMPForging()
{
    PacketGenerator generator;
    generator.setTarget("FF:FF:FF:FF:FF:FF", "FF:FF:FF:FF:FF:FF", "127.0.0.1", "127.0.0.1", 4242, 4243);
    std::string content = "PACKET CONTENT";
    const unsigned char *icmp_packet = generator.createPacket(reinterpret_cast<const unsigned char *>(content.c_str()), content.length(), PacketGenerator::WITH_IPV4 | PacketGenerator::WITH_ICMP);
    QVERIFY2(icmp_packet != nullptr, "TESTNG ERROR : ICMP Packet forging broken");
}

void TestPacketGenerator::testTCPForging()
{
    PacketGenerator generator;
    generator.setTarget("FF:FF:FF:FF:FF:FF", "FF:FF:FF:FF:FF:FF", "127.0.0.1", "127.0.0.1", 4242, 4243);
    std::string content = "PACKET CONTENT";
    const unsigned char *tcp_packet = generator.createPacket(reinterpret_cast<const unsigned char *>(content.c_str()), content.length(), PacketGenerator::WITH_IPV4 | PacketGenerator::WITH_TCP);
    QVERIFY2(tcp_packet != nullptr, "TESTNG ERROR : TCP Packet forging broken");
}

void TestPacketGenerator::testUDPForging()
{
    PacketGenerator generator;
    generator.setTarget("FF:FF:FF:FF:FF:FF", "FF:FF:FF:FF:FF:FF", "127.0.0.1", "127.0.0.1", 4242, 4243);
    std::string content = "PACKET CONTENT";
    const unsigned char *udp_packet = generator.createPacket(reinterpret_cast<const unsigned char *>(content.c_str()), content.length(), PacketGenerator::WITH_IPV4 | PacketGenerator::WITH_UDP);
    QVERIFY2(udp_packet != nullptr, "TESTNG ERROR : UDP Packet forging broken");
}

QTEST_MAIN(TestPacketGenerator)
#include "TestPacketGenerator.moc"
