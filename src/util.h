#ifndef UTIL_H
#define UTIL_H

#include <string>

typedef std::basic_string<unsigned char> OctetString;

std::string hexlify(const unsigned char *data, size_t length, size_t limit=0);
std::string hexlify(const std::string &str, size_t limit=0);
std::string hexlify(const OctetString &data, size_t limit=0);

#endif
