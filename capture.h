#ifndef CAPTURE_H
#define CAPTURE_H

#include <QWidget>

#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <cerrno>
#include <cstring>
#include <QMessageBox>
#include <QTimer>
#include <QListWidgetItem>
#include <QVariant>
#include <string>

#include "CNetworkSniffer.h"

namespace Ui {
class Capture;
}

class Capture : public QWidget
{
    Q_OBJECT

public:
    explicit Capture(QWidget *parent = 0);
    ~Capture();
    bool connectToRawSocket();
    const std::vector<CEthenetFrame *> &getCapturedFrames() const;
    void addPacketToList(unsigned char *buffer, ssize_t total_len);

private slots:
    void captureEverything();
    void onListItemClicked(QListWidgetItem *item);
    void on_stopCapture_clicked();
    void on_filterPushButton_clicked();

private:
    std::string generateListItemText(CEthenetFrame *, ssize_t);
    std::string bufferToStringPrettyfier(const void *object, ssize_t max_len);
    bool keepPacket(CEthenetFrame *frame);
    void addToStats(CEthenetFrame *frame) ;

    const unsigned int MAX_PACKET_LEN = 65536;
    Ui::Capture *ui;
    int sock_raw = -1;
    unsigned char *buffer = new unsigned char[MAX_PACKET_LEN];
    struct sockaddr saddr;
    socklen_t sockaddr_size = sizeof(saddr);
    std::vector<CEthenetFrame *> ethernetFrameVector;
    C_NetworkSniffer sniffer;
    QMessageBox messageBox;
    QTimer *timer = new QTimer(this);

    unsigned int ipv4Stats = 0;
    unsigned int ipv6Stats = 0;
    unsigned int DNSStats = 0;
    unsigned int HTTPStats = 0;
    unsigned int TCPStats = 0;
    unsigned int UDPStats = 0;
    unsigned int ICMPv4Stats = 0;
    unsigned int unknownStats = 0;
    unsigned int ARPStats = 0;
};

#endif // CAPTURE_H
