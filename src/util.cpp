#include "util.h"

std::string hexlify(const unsigned char *data, size_t length, size_t limit)
{
    std::string result;
    char buffer[3];
    for (int i = 0; i < length; i++) {
        if (limit > 0 && i >= limit) {
            result += "...";
            break;
        }
        sprintf(buffer, "%02X", data[i]);
        result += buffer;
    }
    return result;
}

std::string hexlify(const OctetString &data, size_t limit)
{
    return hexlify(data.data(), data.size(), limit);
}
