
#include "hierarchy.h"

bool is_self_signed(const Certificate &cert)
{
    return is_issuer(cert, cert);
}

/**
 * @brief is_issuer
 * @param cert_issuer
 * @param cert_child
 * @return
 *
 * Tell if a certificate is a valid issuer of another certificate.
 *
 * - compare issuer/subject properties
 * - compare extensions ...
 * - verify signature
 */
bool is_issuer(const Certificate &cert_issuer, const Certificate &cert_child)
{
    if (cert_issuer.tbs_certificate.subject != cert_child.tbs_certificate.issuer) {
        return false;
    }

    // Look at extensions
    // id-ce-authorityKeyIdentifier


    // Verify signature

    return true;
}
