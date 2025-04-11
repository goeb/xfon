#include <assert.h>

#include "hierarchy.h"
#include "oid_name.h"

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
    auto it = cert_child.tbs_certificate.extensions.items.find(oid_get_id("id-ce-authorityKeyIdentifier"));
    if (it != cert_child.tbs_certificate.extensions.items.end()) {
        // Extension found
        AuthorityKeyIdentifier akid = std::any_cast<AuthorityKeyIdentifier>(it->second.extn_value);
    }

    // Verify signature

    return true;
}
