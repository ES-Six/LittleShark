//
// Created by brendan on 13/10/18.
//

#include <iostream>

#include "MyLibPCAP/header/PCAPFileReader.h"
#include "MyLibPCAP/header/PCAPFileWriter.h"

int main(int argc, char **argv)
{
    //Créer le file writer et le file reader
    MyLibPCAP::PCAPFileReader test = MyLibPCAP::PCAPFileReader("../test_ping.pcap");
    MyLibPCAP::PCAPFileWriter test_writer = MyLibPCAP::PCAPFileWriter("../my_own.pcap", 1);

    //Informer de l'endianess du fichier lu (la lib le gère automatiquement)
    if (test.getFileEndianess() == MyLibPCAP::pcap_endianess::IS_IDENTICAL) {
        std::cout << "File is little endian" << std::endl;
    } else if (test.getFileEndianess() == MyLibPCAP::pcap_endianess::IS_SWAPPED) {
        std::cout << "File is big endian" << std::endl;
    } else {
        std::cout << "Unsuported endianess" << std::endl;
        return 0;
    }


    //Lire tout les packets du fichier et écrire les packets dans un nouveau PCAP
    std::cout << std::endl;
    while (test.hasNextPacket()) {
        MyLibPCAP::PacketWrapper *packetWrapper = test.getNextPacket();

        if (packetWrapper->getPacketHeader()->caplen == packetWrapper->getPacketHeader()->len) {
            std::cout << "Read a complete packet from file : " << packetWrapper->getPacketHeader()->caplen << " bytes" << std::endl;
            test_writer.writePacketToFile(packetWrapper->getPacketContent(), packetWrapper->getPacketHeader()->caplen, packetWrapper->getPacketHeader()->ts_sec, packetWrapper->getPacketHeader()->ts_usec);
        } else if (packetWrapper->getPacketHeader()->caplen < packetWrapper->getPacketHeader()->len) {
            std::cout << "Read a packet portion from file : " << packetWrapper->getPacketHeader()->caplen << " of " << packetWrapper->getPacketHeader()->len << std::endl;
        } else {
            // This should not be reached at all except in case of corrupted header file or corrupted pkt header
            std::cout << "CRITICAL FAILURE, EVERTING IS GONNA TO EXPLODE" << std::endl;
        }
        delete packetWrapper;

        std::cout << std::endl;
    }

    return 0;
}