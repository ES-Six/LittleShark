#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "PCAPFileWriter.h"
#include "PCAPFileReader.h"
#include "CEthenetFrame.h"
#include <iostream>
#include <ctime>
#include <QFileDialog>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->homeWidget = new Home();
    MainWindow::setCentralWidget(this->homeWidget);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_actionLive_capture_triggered()
{
    this->captureWidget = new Capture();
    this->captureWidget->connectToRawSocket();
    MainWindow::setCentralWidget(this->captureWidget);
}

void MainWindow::on_actionLoad_from_file_triggered()
{
    this->captureWidget = new Capture();

    QString fileName = QFileDialog::getOpenFileName(this,
            tr("Open PCAP file"), "",
            tr("PCAP file (*.pcap);;All Files (*)"));

    MyLibPCAP::PCAPFileReader test = MyLibPCAP::PCAPFileReader(fileName.toStdString().c_str());

    while (test.hasNextPacket()) {
        MyLibPCAP::PacketWrapper *packetWrapper = test.getNextPacket();
        if (packetWrapper->getPacketHeader()->caplen == packetWrapper->getPacketHeader()->len) {
            this->captureWidget->addPacketToList(packetWrapper->getPacketContent(), packetWrapper->getPacketHeader()->caplen);
        }
        delete packetWrapper;
    }
    MainWindow::setCentralWidget(this->captureWidget);
}

void MainWindow::on_actionSave_to_file_triggered()
{
    if (this->captureWidget == nullptr) {
        QMessageBox::information(this, "Nothing to save", "Please start a live capture or load a .pcap file");
        return;
    }

    QString fileName = QFileDialog::getSaveFileName(this,
            tr("Save to PCAP file"), "",
            tr("PCAP file (*.pcap);;All Files (*)"));

    // 1 = ethernet pcap link type
    MyLibPCAP::PCAPFileWriter pcap_writer = MyLibPCAP::PCAPFileWriter(fileName.toStdString().c_str(), 1);
    for (CEthenetFrame *frame : this->captureWidget->getCapturedFrames()) {
        std::time_t result = std::time(nullptr);
        pcap_writer.writePacketToFile(
            reinterpret_cast<char *>(frame->getEthernetFrame()),
            frame->getTotalLen(),
            result,
            0);
    }
    std::cout << "SAVE !" << std::endl;
}

void MainWindow::on_actionPacket_forging_triggered()
{
    this->forgeWidget = new Forge();
    MainWindow::setCentralWidget(this->forgeWidget);
}

void MainWindow::on_actionExit_triggered()
{
    QCoreApplication::quit();
}
