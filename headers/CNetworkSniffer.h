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
    C_NetworkSniffer() = default;
    ~C_NetworkSniffer() = default;

    CEthenetFrame *parse(unsigned char *buffer, ssize_t);

    static std::string bufferToStringPrettyfier(const void *object, ssize_t max_len);
};