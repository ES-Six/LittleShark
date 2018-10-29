#-------------------------------------------------
#
# Project created by QtCreator 2018-10-28T09:12:13
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = LittleShark
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += main.cpp\
        mainwindow.cpp \
    home.cpp \
    capture.cpp \
    forge.cpp \
    CEthenetFrame.cpp \
    CNetworkSniffer.cpp \
    CPacket.cpp \
    DNSParser.cpp \
    httpDetector.cpp \
    PacketGenerator.cpp \
    packet_wrapper.cpp \
    PCAPFileReader.cpp \
    PCAPFileWriter.cpp

HEADERS  += mainwindow.h \
    home.h \
    capture.h \
    forge.h \
    CEthenetFrame.h \
    CNetworkSniffer.h \
    CPacket.h \
    DNSParser.h \
    httpDetector.h \
    PacketGenerator.h \
    packet_wrapper.h \
    pcap_file_headers.h \
    PCAPFileReader.h \
    PCAPFileWriter.h

FORMS    += mainwindow.ui \
    home.ui \
    capture.ui \
    forge.ui
