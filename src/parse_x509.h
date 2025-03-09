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

struct Certificate {
    std::map<PropertyName, PropertyValue> properties;
    std::map<ObjectIdentifier, Extension> extensions;
    void *opaque;
};

std::string oid_get_name(const std::string &oid, bool shortname=false);

int x509_parse_der(const std::string &der_bytes, Certificate &cert);
void x509_free(Certificate &cert);

std::string base64_decode(const std::string &base64lines);
