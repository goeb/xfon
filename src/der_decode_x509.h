#ifndef DER_DECODE_X509_H
#define DER_DECODE_X509_H

#include <openssl/types.h>
#include <string>

#include "certificate.h"
#include "data_model.h"
#include "util.h"

int der_decode_x509_certificate(const OctetString &der_bytes, Certificate &cert);
int der_decode_x509_basic_constraints(const OctetString &der_bytes, size_t &i_start, size_t i_end, Value **out);
int der_decode_x509_subject_key_identifier(const OctetString &der_bytes, size_t &i_start, size_t i_end, Value **out);
int der_decode_x509_authority_key_identifier(const OctetString &der_bytes, Value **out);
int der_decode_x509_key_usage(const OctetString &der_bytes, size_t &i_start, size_t i_end, Value **out);
std::string get_bio_mem_string(BIO *buffer);


#endif // DER_DECODE_X509_H
