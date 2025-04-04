#include "oid_name.h"
#include "render_text.h"

std::string x509_name_to_string(const Name &name)
{
    std::string result;
    bool start = true;
    for (auto relative_dn: name) {
        for (auto attribute: relative_dn) {
            if (!start) result += ", ";
            result += oid_get_name(attribute.type, true);
            result += "=";
            result += attribute.value;
            start = false;
        }
    }
    return result;
}

