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
    timer->start(50); //time specified in ms

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

void Capture::captureEverything() {
    ssize_t total_len;
    memset(buffer, 0, MAX_PACKET_LEN);
    total_len = recvfrom(sock_raw, buffer, MAX_PACKET_LEN, MSG_DONTWAIT, &saddr, &sockaddr_size);
    if (total_len > 0) {
        CEthenetFrame *frame = this->sniffer.parse(buffer, total_len);
        ethernetFrameVector.emplace_back(frame);
        QListWidgetItem *itm = new QListWidgetItem();
        itm->setText(this->generateListItemText(frame, total_len).c_str());
        QVariant v;
        v.setValue((void *)frame);
        itm->setData(Qt::UserRole, v);
        ui->listWidget->addItem(itm);
        std::cout << "Packet captured" << std::endl;
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
    std::cout << "List item cicked" << std::endl;

    CEthenetFrame *frame = reinterpret_cast<CEthenetFrame *>(item->data(Qt::UserRole).value<void *>());

    if (frame) {
        const unsigned char *packet = reinterpret_cast<const unsigned char *>(frame->getEthernetFrame());
        ui->packetContentVisualisation->document()->setPlainText(this->bufferToStringPrettyfier(packet, frame->getTotalLen()).c_str());
    }
}

void Capture::addPacketToList(unsigned char *buffer, ssize_t total_len) {
    CEthenetFrame *frame = this->sniffer.parse(buffer, total_len);
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
