#include "util.h"

std::string hexlify(const unsigned char *data, int length)
{
    std::string result;
    char buffer[3];
    for (int i = 0; i < length; i++) {
        sprintf(buffer, "%02X", data[i]);
        result += buffer;
    }
    return result;
}

std::string hexlify(const OctetString &data)
{
    return hexlify(data.data(), data.size());
}
