#include "forge.h"
#include "ui_forge.h"
#include "PacketGenerator.h"
#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <cerrno>
#include <cstring>
#include <QMessageBox>
#include <unistd.h>
#include <features.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <sys/types.h>
#include <ifaddrs.h>

Forge::Forge(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Forge)
{
    ui->setupUi(this);
    ui->protocolSelector->addItem("ICMPv4", PacketGenerator::WITH_ICMP);
    ui->protocolSelector->addItem("TCP", PacketGenerator::WITH_TCP);
    ui->protocolSelector->addItem("UDP", PacketGenerator::WITH_UDP);

    getifaddrs(&addrs);
    tmp = addrs;

    while (tmp)
    {
        if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET) {
            ui->interfaceSelector->addItem(tmp->ifa_name, tmp->ifa_name);
        }

        tmp = tmp->ifa_next;
    }
}

Forge::~Forge()
{
    freeifaddrs(addrs);
    delete ui;
}

void Forge::on_forgeAndSendButton_clicked()
{
    PacketGenerator generator;
    generator.setTarget(ui->senderMACAddr->text().toStdString().c_str(), ui->targetMACAddr->text().toStdString().c_str(), ui->SenderIPAddr->text().toStdString().c_str(), ui->targetIPAddr->text().toStdString().c_str(), ui->sourcePort->text().toInt(), ui->destinationPort->text().toInt());
    const char *packetContent = ui->packetContent->document()->toPlainText().toStdString().c_str();
    unsigned char *packet = generator.createPacket(reinterpret_cast<const unsigned char *>(packetContent), ui->packetContent->document()->toPlainText().length(), PacketGenerator::WITH_IPV4 | PacketGenerator::WITH_TCP);
    if (packet) {
        int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if(sock_raw == -1){
            QMessageBox::critical(this, "Initialisation error", (std::string("Unable to create the socket: ") + std::strerror(errno)).c_str());
            return;
        }

        struct sockaddr_ll sll;
        struct ifreq ifr;

        bzero(&sll, sizeof(sll));
        bzero(&ifr, sizeof(ifr));

        const char *interfaceName = ui->interfaceSelector->currentText().toStdString().c_str();
        if (interfaceName == nullptr) {
            QMessageBox::critical(this, "Failed to get interface name", "Failed to get interface name");
            return;
        }

        strncpy(reinterpret_cast<char *>(ifr.ifr_name), interfaceName, IFNAMSIZ);
        if((ioctl(sock_raw, SIOCGIFINDEX, &ifr)) == -1)
        {
            QMessageBox::critical(this, "Failed to get index", "Error getting interface index");
            return;
        }


        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);


        if((bind(sock_raw, (struct sockaddr *)&sll, sizeof(sll)))== -1)
        {
            QMessageBox::critical(this, "Failed to bind", "Error binding raw socket to interface");
            return;
        }

        ssize_t sent_bytes = 0;
        sent_bytes = (write(sock_raw, packet, static_cast<size_t >(generator.getCreatedPacketSize())));
        if(sent_bytes != generator.getCreatedPacketSize())
        {
            QMessageBox::warning(this, "Packet partially sent", (std::string("Error : Only sent ") + std::to_string(sent_bytes) + " bytes of " + std::to_string(generator.getCreatedPacketSize()) + " bytes").c_str());
            ::close(sock_raw);
        } else {
            QMessageBox::information(this, "Injection success", "Packet injected successfully");
            ::close(sock_raw);
        }
    } else {
        QMessageBox::critical(this, "Packet creator failure", "Failed to create packet");
        return;
    }

    delete[] packet;
}
