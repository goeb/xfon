#include "x509_verify.h"

#include <openssl/asn1.h>
#include <openssl/x509.h>

#include "journal.h"

bool x509_verify_signature(const Certificate_with_links &cert_issuer, const Certificate_with_links &cert_child)
{
    X509 *x509cert_issuer = NULL;
    X509 *x509cert_child = NULL;
    EVP_PKEY *pubkey = NULL;
    int result = false;

    const unsigned char *der_bytes = cert_issuer.der_bytes.data();
    x509cert_issuer = d2i_X509(NULL, &der_bytes, cert_issuer.der_bytes.size());
    if (!x509cert_issuer) {
        LOGERROR("d2i_X509: Cannot load certificate %s", cert_issuer.get_file_location().c_str());
        goto error;
    }
    der_bytes = cert_child.der_bytes.data();
    x509cert_child = d2i_X509(NULL, &der_bytes, cert_child.der_bytes.size());
    if (!x509cert_child) {
        LOGERROR("d2i_X509: Cannot load certificate %s", cert_child.get_file_location().c_str());
        goto error;
    }

    pubkey = X509_get0_pubkey(x509cert_issuer);
    if (!pubkey) {
        LOGERROR("X509_get0_pubkey: Cannot get public key of certficate %s", cert_issuer.get_file_location().c_str());
        goto error;
    }

    result = (1 == X509_verify(x509cert_child, pubkey));

error:
    if (x509cert_issuer) OPENSSL_free(x509cert_issuer);
    if (x509cert_child) OPENSSL_free(x509cert_child);
    return result;
}
