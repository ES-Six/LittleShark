#include "capture.h"
#include "ui_capture.h"
#include "mainwindow.h"

#include <iostream>
#include <unistd.h>

Capture::Capture(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Capture)
{
    ui->setupUi(this);
    ui->protocolFilter->addItem("No filter", 0);
    ui->protocolFilter->addItem("ARP", 555);
    ui->protocolFilter->addItem("ICMPv4", 1);
    ui->protocolFilter->addItem("TCP", 6);
    ui->protocolFilter->addItem("UDP", 17);
    ui->protocolFilter->addItem("DNS", 666);
    ui->protocolFilter->addItem("HTTP", 777);

    ui->stopCapture->setVisible(false);
    ui->filterPushButton->setEnabled(true);

    connect(ui->listWidget, SIGNAL(itemClicked(QListWidgetItem *)),
                this, SLOT(onListItemClicked(QListWidgetItem *)));
}

const std::vector<CEthenetFrame *> &Capture::getCapturedFrames() const {
    return this->ethernetFrameVector;
}

bool Capture::keepPacket(CEthenetFrame *frame) {
    if (frame == nullptr)
        return false;

    char *src_ip = nullptr;
    char *dst_ip = nullptr;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    bool validInt = false;
    uint16_t proto = 0;

    if (frame->isIPv4Protocol()) {
        proto = frame->getIPv4Header()->protocol;
        src_ip = inet_ntoa(*(in_addr*)(&frame->getIPv4Header()->saddr));
        dst_ip = inet_ntoa(*(in_addr*)(&frame->getIPv4Header()->daddr));
        if (frame->getCPacket()->isTCPProtocol()) {
            src_port = ntohs(frame->getCPacket()->getTCPHeader()->th_sport);
            dst_port = ntohs(frame->getCPacket()->getTCPHeader()->th_dport);

            if (ui->protocolFilter->itemData(ui->protocolFilter->currentIndex()) == 666 && !frame->getCPacket()->getDNSParser().isValiddDNSPacket()) {
                return false;
            }
            if (ui->protocolFilter->itemData(ui->protocolFilter->currentIndex()) == 777 && !frame->getCPacket()->getHTTPDetector().isValiddHTTPPacket()) {
                return false;
            }

        } else if (frame->getCPacket()->isUDPProtocol()) {
            src_port = ntohs(frame->getCPacket()->getUDPHeader()->source);
            dst_port = ntohs(frame->getCPacket()->getUDPHeader()->dest);

            if (ui->protocolFilter->itemData(ui->protocolFilter->currentIndex()) == 666 && !frame->getCPacket()->getDNSParser().isValiddDNSPacket()) {
                return false;
            }
            if (ui->protocolFilter->itemData(ui->protocolFilter->currentIndex()) == 777 && !frame->getCPacket()->getHTTPDetector().isValiddHTTPPacket()) {
                return false;
            }
        } else {
            if (ui->protocolFilter->itemData(ui->protocolFilter->currentIndex()) == 666 || ui->protocolFilter->itemData(ui->protocolFilter->currentIndex()) == 777) {
                return false;
            }
        }
    } else {
        if (ui->protocolFilter->itemData(ui->protocolFilter->currentIndex()) == 666 || ui->protocolFilter->itemData(ui->protocolFilter->currentIndex()) == 777) {
            return false;
        }
    }

    if ((ui->filterSrcIP->text().length() > 0 && src_ip == nullptr) ||
            (ui->filterDstIP->text().length() > 0 && dst_ip == nullptr)) {
        return false;
    }

    if (ui->filterSrcIP->text().length() > 0 && ui->filterSrcIP->text() != src_ip) {
        return false;
    }

    if (ui->filterDstIP->text().length() > 0 && ui->filterDstIP->text() != src_ip) {
        return false;
    }

    if (ui->filterSrcPort->text().length() > 0 && ui->filterSrcPort->text().toInt(&validInt, 10) != src_port) {
        return false;
    }

    if (ui->filterDstPort->text().length() > 0 && ui->filterDstPort->text().toInt(&validInt, 10) != dst_port) {
        return false;
    }

    if (ui->protocolFilter->itemData(ui->protocolFilter->currentIndex()) != 555 &&
            ui->protocolFilter->itemData(ui->protocolFilter->currentIndex()) != 666 &&
            ui->protocolFilter->itemData(ui->protocolFilter->currentIndex()) != 777) {
        if (ui->protocolFilter->itemData(ui->protocolFilter->currentIndex()) != 0 && proto != ui->protocolFilter->itemData(ui->protocolFilter->currentIndex())) {
            return false;
        }
    }

    if (ui->protocolFilter->itemData(ui->protocolFilter->currentIndex()) == 555 && !frame->isARPProtocol()) {
        return false;
    }

    if (src_ip != nullptr && dst_ip != nullptr) {
        std::cout << "SRC: " << src_ip << std::endl;
        std::cout << "DST: " << dst_ip << std::endl;
        std::cout << "SRC PORT: " << src_port << std::endl;
        std::cout << "DST PORT: " << dst_port << std::endl;
    }
    return true;
}

std::string Capture::bufferToStringPrettyfier(const void *object, ssize_t max_len)
{
    std::string packet;
    const char * bytes = reinterpret_cast<const char *>(object);
    for(size_t i = 0; i < max_len; i ++)
    {
        if (bytes[i] >= 33 && bytes[i] <= 126) {
            packet += bytes[i];
        } else {
            packet += '.';
        }
    }

    return packet;
}

bool Capture::connectToRawSocket() {
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock_raw == -1) {
        disconnect(timer, SIGNAL(timeout()), this, SLOT(captureEverything()));
        delete timer;
        timer = nullptr;
        QMessageBox::critical(this, "Initialisation error", (std::string("Unable to create the socket: ") + std::strerror(errno)).c_str());
        return false;
    }

    connect(timer, SIGNAL(timeout()), this, SLOT(captureEverything()));
    timer->start(3); //time specified in ms

    ui->filterPushButton->setEnabled(false);
    ui->stopCapture->setVisible(true);
    return true;
}

std::string Capture::generateListItemText(CEthenetFrame *frame, ssize_t total_len) {
    std::string text;

    if (frame->isARPProtocol()) {
        text += "Packet ARP";
    } else if (frame->isIPv4Protocol()) {
        text += "IPv4";
        if (frame->getCPacket() && frame->getCPacket()->isICMPv4Protocol()) {
            text += " + ICMPv4";
        } else if (frame->getCPacket() && frame->getCPacket()->isTCPProtocol()) {
            text += " + TCP";
            if (frame->getCPacket()->getDNSParser().isValiddDNSPacket()) {
                text += " contain DNS header";
            } else if (frame->getCPacket()->getHTTPDetector().isValiddHTTPPacket()) {
                text += " contain HTTP header";
            }
        } else if (frame->getCPacket() && frame->getCPacket()->isUDPProtocol()) {
            text += " + UDP";
            if (frame->getCPacket()->getDNSParser().isValiddDNSPacket()) {
                text += " contain DNS header";
            } else if (frame->getCPacket()->getHTTPDetector().isValiddHTTPPacket()) {
                text += " contain HTTP header";
            }
        }
    } else if (frame->isIPv6Protocol()) {
        text += "Packet using IPv6";
    } else {
        text += "Packet UNKNOWN";
    }

    text += std::string("(") + std::to_string(total_len) + " bytes)";
    return text;
}

void Capture::addToStats(CEthenetFrame *frame) {
    if (frame->isARPProtocol()) {
        this->ARPStats ++;
    } else if (frame->isIPv4Protocol()) {
        this->ipv4Stats ++;
        if (frame->getCPacket() && frame->getCPacket()->isICMPv4Protocol()) {
            this->ICMPv4Stats ++;
        } else if (frame->getCPacket() && frame->getCPacket()->isTCPProtocol()) {
            this->TCPStats ++;
            if (frame->getCPacket()->getDNSParser().isValiddDNSPacket()) {
                this->DNSStats ++;
            } else if (frame->getCPacket()->getHTTPDetector().isValiddHTTPPacket()) {
                this->HTTPStats ++;
            }
        } else if (frame->getCPacket() && frame->getCPacket()->isUDPProtocol()) {
            this->UDPStats ++;
            if (frame->getCPacket()->getDNSParser().isValiddDNSPacket()) {
                this->DNSStats ++;
            } else if (frame->getCPacket()->getHTTPDetector().isValiddHTTPPacket()) {
                this->HTTPStats ++;
            }
        }
    } else if (frame->isIPv6Protocol()) {
        this->ipv6Stats ++;
    } else {
        this->unknownStats ++;
    }

    ui->ARPStats->setText(("ARP: "+std::to_string(this->ARPStats)).c_str());
    ui->ipv4Stats->setText(("IPv4: "+std::to_string(this->ipv4Stats)).c_str());
    ui->ipv6Stats->setText(("IPv6: "+std::to_string(this->ipv6Stats)).c_str());
    ui->TCPStats->setText(("TCP: "+std::to_string(this->TCPStats)).c_str());
    ui->UDPStats->setText(("UDP: "+std::to_string(this->UDPStats)).c_str());
    ui->icmpv4Stats->setText(("ICMPv4: "+std::to_string(this->ICMPv4Stats)).c_str());
    ui->DNSStats->setText(("DNS: "+std::to_string(this->DNSStats)).c_str());
    ui->HTTPStats->setText(("HTTP: "+std::to_string(this->HTTPStats)).c_str());
    ui->unknownStats->setText(("Unknown: "+std::to_string(this->unknownStats)).c_str());
}

void Capture::captureEverything() {
    ssize_t total_len;
    memset(buffer, 0, MAX_PACKET_LEN);
    total_len = recvfrom(sock_raw, buffer, MAX_PACKET_LEN, MSG_DONTWAIT, &saddr, &sockaddr_size);
    if (total_len > 0) {
        CEthenetFrame *frame = this->sniffer.parse(buffer, total_len);
        this->addToStats(frame);
        ethernetFrameVector.emplace_back(frame);
        QListWidgetItem *itm = new QListWidgetItem();
        itm->setText(this->generateListItemText(frame, total_len).c_str());
        QVariant v;
        v.setValue((void *)frame);
        itm->setData(Qt::UserRole, v);
        ui->listWidget->addItem(itm);
    }
    if (errno == EWOULDBLOCK || errno == EAGAIN) {
        return;
    }
    if(total_len < 0){
        std::cerr << "Failed to get packets: " << std::strerror(errno) << std::endl;
        return;
    }
}

void Capture::onListItemClicked(QListWidgetItem *item) {
    CEthenetFrame *frame = reinterpret_cast<CEthenetFrame *>(item->data(Qt::UserRole).value<void *>());
    if(!frame){
        std::cerr << "Unable to fetch the list item" << std::endl;
        return;
    }

    const unsigned char *packet = reinterpret_cast<const unsigned char *>(frame->getEthernetFrame());
    ui->packetContentAnalysisRaw->document()->setPlainText(this->bufferToStringPrettyfier(packet, frame->getTotalLen()).c_str());

    /* Update the type */
    std::string protocol = "Type: ";
    if(frame->isARPProtocol()){
        protocol.append("ARP");
    } else if(frame->isIPv4Protocol()){
        protocol.append("IPV4");
        if(frame->getCPacket()->isTCPProtocol()){
           if(frame->getCPacket()->getDNSParser().isValiddDNSPacket()){
               protocol.append(" DNS(TCP)");
           } else if(frame->getCPacket()->getHTTPDetector().isValiddHTTPPacket()){
               protocol.append(" HTTP(TCP)");
           } else {
               protocol.append(" Unknow(TCP)");
           }
       } else if(frame->getCPacket()->isUDPProtocol()){
           if(frame->getCPacket()->getDNSParser().isValiddDNSPacket()){
               protocol.append(" DNS(UDP)");
           } else if(frame->getCPacket()->getHTTPDetector().isValiddHTTPPacket()){
               protocol.append(" HTTP(UDP)");
           } else {
               protocol.append(" Unknow(UDP)");
           }
       }
    } else if(frame->isIPv6Protocol()){
        protocol.append("IPV6");
    } else {
        protocol.append("Unknow");
    }

    ui->packetProtocol->setText(protocol.c_str());

    /* Update the length */
    auto size = frame->getTotalLen();
    if(size > 0){
        std::string textSize = std::string(std::string("Size: ") + std::to_string(size) + " bytes");
        ui->packetSize->setText(textSize.c_str());
    } else {
        ui->packetSize->setText("Size:");
    }

    /* Update the IPs and ports */
    ui->packetSource->setText("IP Source:");
    ui->packetDestination->setText("IP Destination:");
    ui->packetPortSource->setText("Port Destination: ");
    ui->packetPortDestination->setText("Port Source: ");

    char *src = inet_ntoa(*(in_addr*)(&frame->getIPv4Header()->saddr));
    if(src != nullptr && strlen(src) > 0){
        std::string src_ip = std::string("IP Source: ") + std::string(src);
        ui->packetSource->setText(src_ip.c_str());
    }
    char *dst = inet_ntoa(*(in_addr*)(&frame->getIPv4Header()->daddr));
    if(dst != nullptr && strlen(dst) > 0){
        std::string dst_ip = std::string("IP Destination: ") + std::string(dst);
        ui->packetDestination->setText(dst_ip.c_str());
    }

    uint16_t sport = ntohs(frame->getCPacket()->getUDPHeader()->source);
    uint16_t dport = ntohs(frame->getCPacket()->getUDPHeader()->dest);
    if(sport > 0){
        std::string src_port = std::string("Port Destination: ") + std::to_string(sport);
        ui->packetPortSource->setText(src_port.c_str());
    }
    if(dport > 0){
        std::string dst_port = std::string("Port Source: ") + std::to_string(dport);
        ui->packetPortDestination->setText(dst_port.c_str());
    }
}

void Capture::addPacketToList(unsigned char *buffer, ssize_t total_len) {
    CEthenetFrame *frame = this->sniffer.parse(buffer, total_len);
    this->addToStats(frame);
    ethernetFrameVector.emplace_back(frame);
    QListWidgetItem *itm = new QListWidgetItem();
    itm->setText(this->generateListItemText(frame, total_len).c_str());
    QVariant v;
    v.setValue((void *)frame);
    itm->setData(Qt::UserRole, v);
    ui->listWidget->addItem(itm);
}

Capture::~Capture()
{
    if (timer != nullptr) {
        disconnect(timer, SIGNAL(timeout()), this, SLOT(captureEverything()));
        delete timer;
    }
    if (this->sock_raw != -1) {
        ::close(this->sock_raw);
    }
    delete[] buffer;
    delete ui;
}

void Capture::on_stopCapture_clicked()
{
    ui->filterPushButton->setEnabled(true);
    disconnect(timer, SIGNAL(timeout()), this, SLOT(captureEverything()));
    delete timer;
    timer = nullptr;
    if (this->sock_raw != -1) {
        ::close(this->sock_raw);
    }
    this->sock_raw = -1;
    ui->stopCapture->setText("Stoped !");
    ui->stopCapture->setEnabled(false);
}

void Capture::on_filterPushButton_clicked()
{
    while(ui->listWidget->count()>0)
    {
      ui->listWidget->takeItem(0);
    }
    for (CEthenetFrame *frame : this->ethernetFrameVector) {
        if (this->keepPacket(frame)) {
            QListWidgetItem *itm = new QListWidgetItem();
            itm->setText(this->generateListItemText(frame, frame->getTotalLen()).c_str());
            QVariant v;
            v.setValue((void *)frame);
            itm->setData(Qt::UserRole, v);
            ui->listWidget->addItem(itm);
        }
    }
}
