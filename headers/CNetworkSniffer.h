/*
* Created by Enguerrand
*/

#pragma once

#include <sys/socket.h>
#include <string>

#ifdef __APPLE__
#define iphdr ip
#endif

#include "CEthenetFrame.h"

class C_NetworkSniffer
{
public:
    C_NetworkSniffer();
    ~C_NetworkSniffer();

    CEthenetFrame *parse(unsigned char *buffer, ssize_t);
};