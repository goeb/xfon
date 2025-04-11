#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <map>
#include <set>
#include <string>
#include <any>

#include "data_model.h"

typedef std::string PropertyName;
typedef std::string PropertyValue;
typedef std::string ObjectIdentifier;
typedef std::string Integer;
typedef std::string IA5String;
typedef OctetString AnotherName;
typedef OctetString KeyIdentifier;
typedef Integer CertificateSerialNumber;
typedef OctetString GeneralNames;

struct AttributeTypeAndValue {
    ObjectIdentifier type;
    std::string value;
    bool operator<(const AttributeTypeAndValue& other) const;
    bool operator==(const AttributeTypeAndValue& other) const;
};

typedef std::list<std::set<AttributeTypeAndValue>> Name;

struct AuthorityKeyIdentifier {
    KeyIdentifier key_identifier; // empty if not present
    GeneralNames authority_cert_issuer; // empty if not present
    CertificateSerialNumber authority_cert_serial_number; // empty if not present
};

struct PrivateKeyUsagePeriod {
    std::string not_before; // Format YYYY-MM-DD hh:mm:ss.fff
    std::string not_after; // Format YYYY-MM-DD hh:mm:ss.fff
};

struct BasicConstraints {
    bool ca;
    Integer path_len_constraint; // empty if not present
};

typedef OctetString SubjectKeyIdentifier;
typedef std::set<std::string> KeyUsage;
typedef GeneralNames SubjectAltName;
typedef GeneralNames IssuerAltName;

struct Extension {
    ObjectIdentifier extn_id; // OID in numeric decimal format. Eg: "2.5.29.14"
    bool critical;
    std::any extn_value;
#if 0
    union {
        SubjectKeyIdentifier subject_key_identifier;
        AuthorityKeyIdentifier authority_key_identifier;
        KeyUsage key_usage;
        PrivateKeyUsagePeriod private_key_usage_period;
        OctetString certificate_policies;
        OctetString policy_mappings;
        SubjectAltName subject_alt_name;
        IssuerAltName issuer_alt_name;
        OctetString subject_directory_attributes;
        BasicConstraints basic_constraints;
        OctetString name_constraints;
        OctetString policy_constraints ;
        OctetString crl_distribution_points;
        OctetString ext_key_usage_syntax;
        OctetString inhibit_any_policy;
        OctetString freshest_crl;
        OctetString crl_number;
        OctetString issuing_distribution_point;
        OctetString delta_crl_indicator;
        OctetString crl_reasons;
        OctetString certificate_issuer;
        OctetString hold_instruction_code;
        OctetString invalidity_date;
        OctetString other;
    } extn_value;
#endif
};

struct Extensions {
    std::map<ObjectIdentifier, Extension> items;
};


struct AlgorithmIdentifier {
    std::string algorithm;
    OctetString parameters;
};


struct Validity {
    std::string not_before; // Format YYYY-MM-DD hh:mm:ss.fff
    std::string not_after; // Format YYYY-MM-DD hh:mm:ss.fff
};

struct SubjectPublicKeyInfo {
    AlgorithmIdentifier algorithm;
    OctetString subject_public_key;
};

struct TBSCertificate {
    Integer version;
    Integer serial_number;
    AlgorithmIdentifier signature;
    Name issuer;
    Validity validity;
    Name subject;
    SubjectPublicKeyInfo subject_public_key_info;
    OctetString issuer_unique_id; // emtpy if not present
    OctetString subject_unique_id; // empty if not present
    Extensions extensions;
};

class Certificate {
public:
    //Object *properties;
    TBSCertificate tbs_certificate;
    AlgorithmIdentifier signature_algorithm;
    OctetString signature_value;
    void *opaque; // conveys data in a format specific to the back-end crypto lib
};

#endif
