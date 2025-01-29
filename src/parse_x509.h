#include <list>
#include <map>
#include <string>

typedef std::string PropertyName;
typedef std::string PropertyValue;

struct Certificate {
    std::map<PropertyName, PropertyValue> properties;
    std::list<std::pair<PropertyName, PropertyValue>> extensions;
    void *opaque;
};

int x509_parse_der(const std::string &der_bytes, Certificate &cert);
void x509_free(Certificate &cert);

std::string base64_decode(const std::string &base64lines);
