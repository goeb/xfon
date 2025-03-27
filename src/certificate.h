#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <map>
#include <string>

#include "data_model.h"

typedef std::string PropertyName;
typedef std::string PropertyValue;
typedef std::string ObjectIdentifier;

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

struct AlgorithmIdentifier {
    std::string algorithm;
    std::string parameters;
};

struct Validity {
    std::string not_before;
    std::string not_after;
};

struct SubjectPublicKeyInfo {
    AlgorithmIdentifier algorithm;
    OctetString subject_public_key;

};

struct TBSCertificate {
    long version;
    std::string serial_number;
    AlgorithmIdentifier signature;
    std::string issuer;
    Validity validity;
    std::string subject;
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
