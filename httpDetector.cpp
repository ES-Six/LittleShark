//
// Created by brendan on 23/10/18.
//

#include "httpDetector.h"

#include <iostream>
#include <cstring>

bool httpDetector::parseRequestData(unsigned char *buffer, uint16_t max_len) {
    unsigned char *start = buffer;
    unsigned char *cursor = buffer;
    if (max_len < MIN_METHOD_LENGTH) {
        return false;
    }

    // print_bytes(buffer, max_len);

    bool isMethodValid = false;
    for (std::string method : this->m_vMethodLists) {
        if (strncmp(reinterpret_cast<const char *>(cursor), method.c_str(), method.length()) == 0) {
            cursor += method.length();
            this->method = method;
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
    const std::string reserved_char = "!*'();:@&=+$,/?#[]";
    const std::string standard_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-~";
    int url_count = 0;
    while ((cursor - start < max_len) && *cursor != 0 && (reserved_char.find(*cursor) != std::string::npos || standard_chars.find(*cursor) != std::string::npos)) {
        url_count ++;
        this->url += *cursor;
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
            this->protoVersion = proto;
            isProtoVersionValid = true;
        }
    }
    if (!isProtoVersionValid)
        return false;

    this->isPacketValid = true;
    this->isRequest = true;
    return true;
}

bool httpDetector::parseResponseData(unsigned char *buffer, uint16_t max_len) {
    unsigned char *start = buffer;
    unsigned char *cursor = buffer;

    if (max_len < MIN_METHOD_LENGTH) {
        return false;
    }

    //Vérifier la version du protocol http
    bool isProtoVersionValid = false;
    for (std::string proto : this->m_vProtoVersionLists) {
        if (strncmp(reinterpret_cast<const char *>(cursor), proto.c_str(), proto.length()) == 0) {
            cursor += proto.length();
            this->protoVersion = proto;
            isProtoVersionValid = true;
        }
    }
    if (!isProtoVersionValid)
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

    //Verifier que le code de retour fasse 3 chiffres
    const std::string standard_chars = "0123456789";
    int ret_count = 0;
    while ((cursor - start < max_len) && *cursor != 0 && standard_chars.find(*cursor) != std::string::npos) {
        ret_count ++;
        cursor ++;
    }

    if (*cursor == 0)
        return false;

    if (ret_count != 3)
        return false;

    if (cursor - start >= max_len)
        return false;

    this->isResponse = true;
    this->isPacketValid = true;
    return true;
}

void httpDetector::parseData(unsigned char *buffer, uint16_t max_len) {
    this->url = "";
    this->returnCode = "";
    this->method = "";
    this->protoVersion = "";
    if (!this->parseRequestData(buffer, max_len))
        this->parseResponseData(buffer, max_len);
}

bool httpDetector::isValiddHTTPPacket() const {
    return this->isPacketValid;
}

bool httpDetector::isHTTPRequest() const {
    return this->isRequest;
}

bool httpDetector::isHTTPResponse() const {
    return this->isResponse;
}

const std::string &httpDetector::getUrl() const {
    return this->url;
}

const std::string &httpDetector::getMethod() const {
    return this->method;
}

const std::string &httpDetector::getProtocolVersion() const {
    return this->protoVersion;
}

const std::string &httpDetector::getReturnCode() const {
    return this->returnCode;
}
