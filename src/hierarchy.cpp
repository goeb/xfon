#include <assert.h>

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
    const Value *akidv = cert_child.tbs_certificate.extensions.get("id-ce-authorityKeyIdentifier");
    if (akidv) {
        assert(akidv->get_type() == V_OBJECT);
        const Object *akid = dynamic_cast<const Object *>(akidv);
        const Value *extnvalue = akid->get("extnvalue");
        assert(extnvalue);
        assert(extnvalue->get_type() == V_OBJECT);
        // TODO

    }

    // Verify signature

    return true;
}
