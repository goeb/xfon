#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <list>
#include <map>
#include <set>
#include <string>
#include <any>

#include "util.h"

typedef std::string PropertyName;
typedef std::string PropertyValue;
typedef std::string ObjectIdentifier;
typedef std::string Integer;
typedef std::string IA5String;
typedef OctetString AnotherName;
typedef OctetString KeyIdentifier;
typedef Integer CertificateSerialNumber;

struct AttributeTypeAndValue {
    ObjectIdentifier type;
    std::string value;
    bool operator<(const AttributeTypeAndValue& other) const;
    bool operator==(const AttributeTypeAndValue& other) const;
};

typedef std::list<std::set<AttributeTypeAndValue>> Name;

struct GeneralNames {
    enum {
        TYPE_STR,
        TYPE_NAME,
        TYPE_OTHER
    } type;
    std::string stringvalue;
    Name namevalue;
    OctetString othervalue;
};

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
};

struct Extensions {
    std::map<ObjectIdentifier, Extension> items;
};


struct AlgorithmIdentifier {
    std::string algorithm;
    OctetString parameters;
};


struct Validity {
    std::string not_before; // Format YYYY-MM-DD hh:mm:ss[...]
    std::string not_after; // Format YYYY-MM-DD hh:mm:ss[...]
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
    TBSCertificate tbs_certificate;
    AlgorithmIdentifier signature_algorithm;
    OctetString signature_value;
    OctetString der_bytes; // Full der encoded value, containing the 3 fields above
    std::string filename;
    size_t index_in_file;
    void *opaque; // conveys data in a format specific to the back-end crypto lib
};

#endif
