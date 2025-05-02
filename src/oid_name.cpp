#include <cstddef>

#include "oid_name.h"

struct Oid {
    const char *oid;          // eg: 2.5.29.19
    const char *long_name;    // eg: id-ce-basicConstraints
    const char *short_name;   // eg: basicConstraints
};

static const Oid OID_NAMES[] = {
    { "0.9.2342.19200300.100.1.1", "userid", "uid"},
    { "0.9.2342.19200300.100.1.25", "id-domainComponent", "dc" },
    { "1.2.840.113549.1.9.1", "id-emailAddress", "email" },
    { "2.5.4.3", "id-at-commonName", "cn" },
    { "2.5.4.4", "id-at-surname", "sn" },
    { "2.5.4.5", "id-at-serialNumber", "serial" },
    { "2.5.4.6", "id-at-countryName", "c" },
    { "2.5.4.7", "id-at-localityName", "l" },
    { "2.5.4.8", "id-at-stateOrProvinceName", "st" },
    { "2.5.4.10", "id-at-organizationName", "o" },
    { "2.5.4.11", "id-at-organizationalUnitName", "ou" },
    { "2.5.4.12", "id-at-title", "title" },
    { "2.5.4.41", "id-at-name", "name" },
    { "2.5.4.42", "id-at-givenName", "given-name" },
    { "2.5.4.43", "id-at-initials", "initials" },
    { "2.5.4.44", "id-at-generationQualifier", "generation-qualifier" },
    { "2.5.4.46", "id-at-dnQualifier", "dn-qualifier" },
    { "2.5.4.65", "id-at-pseudonym", "pseudonym" },

    { "2.5.29.14", "id-ce-subjectKeyIdentifier", NULL },
    { "2.5.29.15", "id-ce-keyUsage", NULL },
    { "2.5.29.16", "id-ce-privateKeyUsagePeriod", NULL },
    { "2.5.29.17", "id-ce-subjectAltName", NULL },
    { "2.5.29.18", "id-ce-issuerAltName", NULL },
    { "2.5.29.19", "id-ce-basicConstraints", NULL },
    { "2.5.29.20", "id-ce-cRLNumber", NULL },
    { "2.5.29.21", "id-ce-cRLReasons", NULL },
    { "2.5.29.22", "id-ce-instructionCode", NULL },
    { "2.5.29.23", "id-ce-holdInstructionCode", NULL },
    { "2.5.29.24", "id-ce-invalidityDate", NULL },
    { "2.5.29.27", "id-ce-deltaCRLIndicator", NULL },
    { "2.5.29.28", "id-ce-issuingDistributionPoint", NULL },
    { "2.5.29.29", "id-ce-certificateIssuer", NULL },
    { "2.5.29.30", "id-ce-nameConstraints", NULL },
    { "2.5.29.31", "id-ce-cRLDistributionPoints", NULL },
    { "2.5.29.32", "id-ce-certificatePolicies", NULL },
    { "2.5.29.33", "id-ce-policyMappings", NULL },
    { "2.5.29.35", "id-ce-authorityKeyIdentifier", NULL },
    { "2.5.29.36", "id-ce-policyConstraints", NULL },
    { "2.5.29.37", "id-ce-extKeyUsage", NULL },
    { NULL, NULL, NULL }
};

std::string oid_get_name(const std::string &oid, bool shortname)
{
    const struct Oid *ptr_oid = OID_NAMES;
    while (ptr_oid->oid) {
        if (oid == ptr_oid->oid) {
            return shortname?ptr_oid->short_name:ptr_oid->long_name;
        }
        ptr_oid++;
    }
    return oid;
}

/**
 * Convert a name (long or short) to a numerical OID
 *
 * name can be a long or short name, or a numerical OID
 * (no conversion is done in this latter case).
 */
std::string oid_get_id(const std::string &name)
{
    const struct Oid *ptr_oid = OID_NAMES;
    while (ptr_oid->oid) {
        if (ptr_oid->long_name && name == ptr_oid->long_name) return ptr_oid->oid;
        if (ptr_oid->short_name && name == ptr_oid->short_name) return ptr_oid->oid;
        if (name == ptr_oid->oid) return ptr_oid->oid;
        ptr_oid++;
    }
    return ""; // not found
}

