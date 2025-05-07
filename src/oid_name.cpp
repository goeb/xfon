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
    { "1.2.840.10045.2.1", "ecPublicKey", NULL },
    { "1.2.840.10045.4.3.2", "ecdsa-with-SHA256", NULL },
    { "1.2.840.10045.4.3.3", "ecdsa-with-SHA384", NULL },
    { "1.2.840.113549.1.1.1", "rsaEncryption", NULL },
    { "1.2.840.113549.1.1.5", "sha1-with-rsa-signature", NULL },
    { "1.2.840.113549.1.1.11", "sha256WithRSAEncryption", NULL },
    { "1.2.840.113549.1.1.12", "sha384WithRSAEncryption", NULL },
    { "1.2.840.113549.1.1.13", "sha512WithRSAEncryption", NULL },
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
    { "2.5.4.42", "id-at-givenName", "givenName" },
    { "2.5.4.43", "id-at-initials", "initials" },
    { "2.5.4.44", "id-at-generationQualifier", "generationQualifier" },
    { "2.5.4.46", "id-at-dnQualifier", "dnQualifier" },
    { "2.5.4.65", "id-at-pseudonym", "pseudonym" },

    { "2.5.29.14", "id-ce-subjectKeyIdentifier", "subjectKeyIdentifier" },
    { "2.5.29.15", "id-ce-keyUsage", "keyUsage" },
    { "2.5.29.16", "id-ce-privateKeyUsagePeriod", "privateKeyUsagePeriod" },
    { "2.5.29.17", "id-ce-subjectAltName", "subjectAltName" },
    { "2.5.29.18", "id-ce-issuerAltName", "issuerAltName" },
    { "2.5.29.19", "id-ce-basicConstraints", "basicConstraints" },
    { "2.5.29.20", "id-ce-cRLNumber", "cRLNumber" },
    { "2.5.29.21", "id-ce-cRLReasons", "cRLReasons" },
    { "2.5.29.22", "id-ce-instructionCode", "instructionCode" },
    { "2.5.29.23", "id-ce-holdInstructionCode", "holdInstructionCode" },
    { "2.5.29.24", "id-ce-invalidityDate", "invalidityDate" },
    { "2.5.29.27", "id-ce-deltaCRLIndicator", "deltaCRLIndicator" },
    { "2.5.29.28", "id-ce-issuingDistributionPoint", "issuingDistributionPoint" },
    { "2.5.29.29", "id-ce-certificateIssuer", "certificateIssuer" },
    { "2.5.29.30", "id-ce-nameConstraints", "nameConstraints" },
    { "2.5.29.31", "id-ce-cRLDistributionPoints", "cRLDistributionPoints" },
    { "2.5.29.32", "id-ce-certificatePolicies", "certificatePolicies" },
    { "2.5.29.33", "id-ce-policyMappings", "policyMappings" },
    { "2.5.29.35", "id-ce-authorityKeyIdentifier", "authorityKeyIdentifier" },
    { "2.5.29.36", "id-ce-policyConstraints", "policyConstraints" },
    { "2.5.29.37", "id-ce-extKeyUsage", "extKeyUsage" },
    { NULL, NULL, NULL }
};

std::string oid_get_name(const std::string &oid, bool shortname)
{
    const struct Oid *ptr_oid = OID_NAMES;
    while (ptr_oid->oid) {
        if (oid == ptr_oid->oid) {
            if (shortname && ptr_oid->short_name) {
                return ptr_oid->short_name;
            } else {
                return ptr_oid->long_name;
            }
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

