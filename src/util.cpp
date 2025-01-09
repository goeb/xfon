#include "util.h"

std::string hexlify(const unsigned char *data, size_t length, size_t limit)
{
    std::string result;
    char buffer[3];
    for (size_t i = 0; i < length; i++) {
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

/**
 * @brief Decode a base64-encoded string
 * @param base64
 * @return
 *     Empty octet string on error
 *     Otherwise, the decoded octet string
 */
OctetString base64_decode(const std::string &base64)
{
    unsigned int triplet = 0; // decoded triplet (from 4 b64 characters)
    int src_index = 0;
    size_t src_len = base64.size();
    OctetString result;

    for (size_t i=0; i<src_len; i++) {
        unsigned int b64code = 0;
        unsigned char b64char = (unsigned char)base64[i];
        src_index++;

        /* alphabet defined in RFC 4648 */
        if (b64char >= 'A' && b64char <= 'Z') b64code = b64char - 'A';           // 0..25
        else if (b64char >= 'a' && b64char <= 'z') b64code = b64char - 'a' + 26; // 26..51
        else if (b64char >= '0' && b64char <= '9') b64code = b64char - '0' + 52; // 52..61
        else if (b64char == '+') b64code = 62;                                   // 62
        else if (b64char == '/') b64code = 63;                                   // 63
        else if (b64char == '=') {
            switch ((src_index-1) % 4) {
            case 0:
                fprintf(stderr, "base64_decode: invalid character '=' aligned on 4\n");
                return OctetString();
            case 1:
                fprintf(stderr, "base64_decode: invalid character '=' aligned on 4 + 1\n");
                return OctetString();
            case 2:
                if ( (i >= base64.size() -1 || base64[i+1] != '=') ) {
                    fprintf(stderr, "base64_decode: invalid character '=' followed by other\n");
                    return OctetString();
                }
                // Two b64 characters encode 1 character
                result += (unsigned char) (triplet >> 4);
                return result;
            case 3:
                // 3 b64 codes encode 2 characters
                result += (unsigned char) (triplet >> 10);
                result += (unsigned char) (triplet >> 2);
                return result;
            }
        } else {
            fprintf(stderr, "invalid base64 character: '%c'\n", base64[i]);
            return OctetString();
        }

        triplet = (triplet << 6) | b64code;
        if (0 == (src_index % 4)) {
            result += (unsigned char) (triplet >> 16);
            result += (unsigned char) (triplet >> 8);
            result += (unsigned char) triplet;
            triplet = 0;
        }
    }
    return result;
}
