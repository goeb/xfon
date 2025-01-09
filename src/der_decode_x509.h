#ifndef DER_DECODE_X509_H
#define DER_DECODE_X509_H

#include "certificate.h"
#include "util.h"

int der_decode_x509_certificate(const OctetString &der_bytes, Certificate &cert);

#endif // DER_DECODE_X509_H
