#include <list>
#include <map>
#include <string>

typedef std::string PropertyName;
typedef std::string PropertyValue;
typedef std::string ObjectIdentifier;

struct Extension {
    bool critical;
    std::string extn_value;
};

struct Certificate {
    std::map<PropertyName, PropertyValue> properties;
    std::map<ObjectIdentifier, Extension> extensions;
    void *opaque;
};

std::string hexdump(const unsigned char *data, int length);
std::string hexdump(const std::string &str);
int x509_parse_der(const std::string &der_bytes, Certificate &cert);
void x509_free(Certificate &cert);

std::string base64_decode(const std::string &base64lines);
