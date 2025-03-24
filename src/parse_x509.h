#include <map>
#include <string>

#include "certificate.h"
#include "data_model.h"

int x509_parse_der(const std::string &der_bytes, Certificate &cert);
void x509_free(Certificate &cert);

std::string base64_decode(const std::string &base64lines);
