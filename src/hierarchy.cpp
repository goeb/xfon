#include <assert.h>

#include "hierarchy.h"
#include "journal.h"
#include "oid_name.h"

static bool is_self_signed(const Certificate_with_links &cert)
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
static bool is_issuer(const Certificate_with_links &cert_issuer, const Certificate_with_links &cert_child)
{
    if (cert_issuer.tbs_certificate.subject != cert_child.tbs_certificate.issuer) {
        return false;
    }

    return true; // TODO

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

static void prune_duplicates(std::vector<Certificate_with_links> &certificates)
{
    std::vector<Certificate_with_links>::iterator cert1;
    std::vector<Certificate_with_links>::iterator cert2;
    LOGDEBUG("certificates.size()=%lu", certificates.size());
    size_t len = certificates.size();
    for (cert1=certificates.begin(); cert1!=certificates.end(); cert1++) {
        for (cert2=cert1+1; cert2!=certificates.end();) {
            if (cert1->der_bytes == cert2->der_bytes) {
                // Same certificates. Remove the second
                LOGWARNING("Duplicate certificate %s:%lu ignored (same as %s:%lu)",
                           cert2->filename.c_str(), cert2->index_in_file,
                           cert1->filename.c_str(), cert1->index_in_file);
                cert2 = certificates.erase(cert2);
            } else {
                cert2++;
            }
        }
    }
}

/**
 * - Remove duplicates
 * - Draw parent-child relationships
 * - Break circular loops
 * - Remove multiple parents (eg: same authorities and keys, but different validity dates)
 * - Simplify parallel descendants (eg: a certificate is both a child and a grand-child)
 */
std::vector<Certificate_with_links> compute_hierarchy(const std::vector<Certificate> &certificates)
{
    std::vector<Certificate_with_links> certs;
    for (auto cert: certificates) {
        certs.push_back(Certificate_with_links(cert));
    }

    // Remove duplicates
    prune_duplicates(certs);

    // Draw parent-child relationships
    std::vector<Certificate_with_links>::iterator cert1;
    std::vector<Certificate_with_links>::iterator cert2;
    for (cert1=certs.begin(); cert1!=certs.end(); cert1++) {
        for (cert2=cert1+1; cert2!=certs.end();) {
            if (is_issuer(*cert1, *cert2)) {
                // cert1 is parent of cert2
                cert1->children.push_back(&*cert2);
                cert2->parents.push_back(&*cert1);
            }
            if (is_issuer(*cert2, *cert1)) {
                // cert2 is parent of cert1
                cert2->children.push_back(&*cert1);
                cert1->parents.push_back(&*cert2);
            }
    }

    // Break circular loops
    // - in favor the the longest lineage

    // Remove multiple parents (eg: same authorities and keys, but different validity dates)
    // - in favor the the longest lineage

    // Simplify parallel descendants (eg: a certificate is both a child and a grand-child)
    // - in favor the the longest lineage

    return certs;
}
