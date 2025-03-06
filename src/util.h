#ifndef UTIL_H
#define UTIL_H

#include <string>

typedef std::basic_string<unsigned char> OctetString;

std::string hexlify(const unsigned char *data, int length);
std::string hexlify(const std::string &str);
std::string hexlify(const OctetString &data);

#endif
