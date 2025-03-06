#include <cstddef>

#include "oid_name.h"

struct Oid {
    const char *oid;          // eg: 2.5.29.19
    const char *long_name;    // eg: id-ce-basicConstraints
    const char *short_name;   // eg: basicConstraints
};

static const Oid OID_NAMES[] = {
    { "2.5.29.14", "id-ce-subjectKeyIdentifier", NULL },
    { "2.5.29.15", "id-ce-keyUsage", NULL },
    { "2.5.29.16", "id-ce-privateKeyUsagePeriod", NULL },
    { "2.5.29.17", "id-ce-subjectAltName", NULL },
    { "2.5.29.18", "id-ce-issuerAltName", NULL },
    { "2.5.29.19", "id-ce-basicConstraints", NULL },
    { "2.5.29.20", "id-ce-cRLNumber", NULL },
    { "2.5.29.21", "id-ce-reasonCode", NULL },
    { "2.5.29.22", "id-ce-instructionCode", NULL },
    { "2.5.29.23", "id-ce-invalidityDate", NULL },
    { "2.5.29.24", "id-ce-issuingDistributionPoint", NULL },
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
        if (oid == ptr_oid->oid) return shortname?ptr_oid->short_name:ptr_oid->long_name;
        ptr_oid++;
    }
    return oid;
}
