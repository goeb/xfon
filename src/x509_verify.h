#ifndef X509_VERIFY_H
#define X509_VERIFY_H

#include "hierarchy.h"

bool x509_verify_signature(const Certificate_with_links &cert_issuer, const Certificate_with_links &cert_child);

#endif // X509_VERIFY_H
