#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <map>
#include <set>
#include <string>

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

struct Extension {
    bool critical;
    Value *extn_value;
    Extension() : critical(false), extn_value(0) {}
    ~Extension() {
        if (extn_value) delete extn_value;
    }
    // Make it no copyable (because of the extn_value pointer that is not handled for copy)
    Extension(const Extension&) = delete;
    Extension& operator=(const Extension&) = delete;
};

struct AuthorityKeyIdentifier {
    KeyIdentifier *key_identifier;
    GeneralNames *authority_cert_issuer;
    CertificateSerialNumber *authority_cert_serial_number;
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
    Object extensions;
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
