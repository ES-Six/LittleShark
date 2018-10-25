cmake_minimum_required(VERSION 3.12)
project(little_shark)

set(CMAKE_CXX_STANDARD 14)

add_library(my_libpcap MyLibPCAP/src/PCAPFileReader.cpp MyLibPCAP/header/PCAPFileReader.h main.cpp MyLibPCAP/header/pcap_file_headers.h MyLibPCAP/header/packet_wrapper.h MyLibPCAP/src/packet_wrapper.cpp MyLibPCAP/header/PCAPFileWriter.h MyLibPCAP/src/PCAPFileWriter.cpp)
add_executable(test.elf main.cpp MyLibPCAP/header/PCAPFileReader.h srcs/CCore.cpp srcs/CNetworkSniffer.cpp srcs/CPacket.cpp headers/CCore.h headers/CNetworkSniffer.h headers/CPacket.h srcs/CEthenetFrame.cpp headers/CEthenetFrame.h srcs/DNSParser.cpp headers/DNSParser.h srcs/httpDetector.cpp headers/httpDetector.h srcs/PacketGenerator.cpp headers/PacketGenerator.h)
target_link_libraries(test.elf my_libpcap)