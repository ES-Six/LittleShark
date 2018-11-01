QT += widgets testlib

HEADERS         += ../PacketGenerator.h \
    ../PCAPFileReader.h \
    ../packet_wrapper.h \
    ../CEthenetFrame.h \
    ../CNetworkSniffer.h \
    ../CPacket.h \
    ../DNSParser.h \
    ../httpDetector.h


SOURCES		= \
    ../PacketGenerator.cpp \
    UnitTests.cpp \
    ../PCAPFileReader.cpp \
    ../packet_wrapper.cpp \
    ../CEthenetFrame.cpp \
    ../CNetworkSniffer.cpp \
    ../CPacket.cpp \
    ../DNSParser.cpp \
    ../httpDetector.cpp

TARGET          = qtunit-example
