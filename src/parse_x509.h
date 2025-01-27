#include <map>
#include <string>

std::map<std::string, std::string> parse_x509_der(const std::string &der_bytes);
std::string base64_decode(const std::string &base64lines);
