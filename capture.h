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

private:
    std::string generateListItemText(CEthenetFrame *, ssize_t);
    std::string bufferToStringPrettyfier(const void *object, ssize_t max_len);

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
};

#endif // CAPTURE_H
