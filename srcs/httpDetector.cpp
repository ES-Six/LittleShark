//
// Created by brendan on 23/10/18.
//

#include "../headers/httpDetector.h"

#include <iostream>
#include <cstring>

bool httpDetector::parseRequestData(unsigned char *buffer, uint16_t max_len) {
    unsigned char *start = buffer;
    unsigned char *cursor = buffer;
    if (max_len < MAX_METHOD_LENGTH) {
        std::cout << "This packet doesn't contain HTTP header" << std::endl;
        return false;
    }

    // print_bytes(buffer, max_len);

    bool isMethodValid = false;
    for (std::string method : this->m_vMethodLists) {
        if (strncmp(reinterpret_cast<const char *>(cursor), method.c_str(), method.length()) == 0) {
            cursor += method.length();
            isMethodValid = true;
        }
    }
    if (!isMethodValid)
        return false;

    int space_count = 0;
    //Sauter les espaces
    while ((cursor - start < max_len) && *cursor != 0 && (*cursor == ' ' || *cursor == '\t')) {
        space_count ++;
        cursor ++;
    }

    if (*cursor == 0)
        return false;

    if (!space_count)
        return false;

    if (cursor - start >= max_len)
        return false;

    //Verifier l'url
    std::string reserved_char = "!*'();:@&=+$,/?#[]";
    std::string standard_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-~";
    int url_count = 0;
    while ((cursor - start < max_len) && *cursor != 0 && (reserved_char.find(*cursor) != std::string::npos || standard_chars.find(*cursor) != std::string::npos)) {
        url_count ++;
        cursor ++;
    }

    if (*cursor == 0)
        return false;

    if (!url_count)
        return false;

    if (cursor - start >= max_len)
        return false;

    //Sauter les espaces
    space_count = 0;
    while ((cursor - start < max_len) && *cursor != 0 && (*cursor == ' ' || *cursor == '\t')) {
        space_count ++;
        cursor ++;
    }

    if (*cursor == 0)
        return false;

    if (!space_count)
        return false;

    if (cursor - start >= max_len)
        return false;

    //Vérifier la version du protocol http
    bool isProtoVersionValid = false;
    for (std::string proto : this->m_vProtoVersionLists) {
        if (strncmp(reinterpret_cast<const char *>(cursor), proto.c_str(), proto.length()) == 0) {
            cursor += proto.length();
            isProtoVersionValid = true;
        }
    }
    if (!isProtoVersionValid)
        return false;

    this->isPacketValid = true;
    return true;
}

bool httpDetector::parseResponseData(unsigned char *buffer, uint16_t max_len) {
    return true;
}

void httpDetector::parseData(unsigned char *buffer, uint16_t max_len) {
    if (!this->parseRequestData(buffer, max_len))
        this->parseResponseData(buffer, max_len);
}

bool httpDetector::isValiddHTTPPacket() const {
    return this->isPacketValid;
}