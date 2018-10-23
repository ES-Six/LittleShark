//
// Created by brendan on 23/10/18.
//

#ifndef LITTLE_SHARK_HTTPDETECTOR_H
#define LITTLE_SHARK_HTTPDETECTOR_H

#include <string>
#include <vector>

class httpDetector {
public:
    httpDetector() = default;
    ~httpDetector() = default;
    void parseData(unsigned char *, uint16_t);
    bool isValiddHTTPPacket() const;
    bool parseRequestData(unsigned char *, uint16_t);
    bool parseResponseData(unsigned char *, uint16_t);
private:
    std::string url;
    std::string method;
    std::string protoVersion;
    bool isPacketValid = false;
    const uint16_t MAX_METHOD_LENGTH = 7;
    std::vector<const char *> m_vMethodLists = {
        "GET",
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "CONNECT",
        "OPTIONS",
        "TRACE"
    };

    std::vector<const char *> m_vProtoVersionLists = {
        "HTTP/1.1",
        "HTTP/2.0",
    };
};


#endif //LITTLE_SHARK_HTTPDETECTOR_H
