#include <iostream>

#include "MyLibPCAP/header/PCAPFileReader.h"
#include "MyLibPCAP/header/PCAPFileWriter.h"
#include "headers/CCore.h"
#include "headers/PacketGenerator.h"

#include <sys/socket.h>
#include <unistd.h>
#include <cstdlib>
#include <sys/ioctl.h>
#include <features.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <cstring>

int main(int argc, char **argv)
{
    // Exemple d'utilisation de mylibpcap : la lib pour lire les fichiers .pcap
    /*
    //Créer le file writer et le file reader
    MyLibPCAP::PCAPFileReader test = MyLibPCAP::PCAPFileReader("../pcap_test_files/test_ping.pcap");
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
            // test_writer.writePacketToFile(packetWrapper->getPacketContent(), packetWrapper->getPacketHeader()->caplen, packetWrapper->getPacketHeader()->ts_sec, packetWrapper->getPacketHeader()->ts_usec);
            C_NetworkSniffer sniffer;
            CEthenetFrame *frame = sniffer.parse(packetWrapper->getPacketContent(), packetWrapper->getPacketHeader()->caplen);
            C_Core tmp;
            tmp.printEthernetFrameProtocol(frame, packetWrapper->getPacketHeader()->caplen);

        } else if (packetWrapper->getPacketHeader()->caplen < packetWrapper->getPacketHeader()->len) {
            std::cout << "Read a packet portion from file : " << packetWrapper->getPacketHeader()->caplen << " of " << packetWrapper->getPacketHeader()->len << std::endl;
        } else {
            // This should not be reached at all except in case of corrupted header file or corrupted pkt header
            std::cout << "CRITICAL FAILURE, EVERTING IS GONNA TO EXPLODE" << std::endl;
        }
        delete packetWrapper;

        std::cout << std::endl;
    }
    */


    //Exemple d'injection de packets
    /*
    PacketGenerator generator;
    std::string exemple_buffer = "Loulilol";
    generator.setTarget("f8:00:54:11:11:1d", "f8:01:54:11:01:1d", "127.0.0.1", "127.0.0.1", 7654, 7654);
    auto buffer = reinterpret_cast<const unsigned char *>(exemple_buffer.c_str());
    unsigned char *packet = generator.createPacket(buffer, exemple_buffer.length(), PacketGenerator::WITH_IPV4 | PacketGenerator::WITH_TCP);
    if (packet) {
        std::cout << "Created a " << std::to_string(generator.getCreatedPacketSize()) << " bytes packet succesfully, ready to send" << std::endl;

        int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if(sock_raw == -1){
            std::cerr << "Unable to create the socket..." << std::endl;
            return 1;
        }

        struct sockaddr_ll sll;
        struct ifreq ifr;

        bzero(&sll, sizeof(sll));
        bzero(&ifr, sizeof(ifr));

        strncpy(reinterpret_cast<char *>(ifr.ifr_name), "wlo1", IFNAMSIZ);
        if((ioctl(sock_raw, SIOCGIFINDEX, &ifr)) == -1)
        {
            printf("Error getting Interface index !\n");
            exit(-1);
        }


        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);


        if((bind(sock_raw, (struct sockaddr *)&sll, sizeof(sll)))== -1)
        {
            perror("Error binding raw socket to interface\n");
            exit(-1);
        }


        ssize_t sent_bytes = 0;
        sent_bytes = (write(sock_raw, packet, static_cast<size_t >(generator.getCreatedPacketSize())));
        if(sent_bytes != generator.getCreatedPacketSize())
        {
            std::cerr << "Error : Only sent " << sent_bytes << "bytes of " << generator.getCreatedPacketSize() << " bytes" << std::endl;
            return 1;
        } else {
            std::cout << "Packet injected successfully !!" << std::endl;
            return 0;
        }
    } else {
        std::cerr << "Failed to create packet..." << std::endl;
        return 2;
    }

    delete[] packet;

    return 0;
    */

    // Exemple de lancement du core d'analse réseau de little shark
    auto pCore = new C_Core();
    pCore->Process();

    return 0;
}