#include "oid_name.h"
#include "render_text.h"

std::string to_string(const Name &name)
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

std::string to_string(bool boolean)
{
    if (boolean) return "true";
    else return "false";
}

std::string to_string(const BasicConstraints &basic_constraints)
{
    std::string result;
    result += "cA:" + to_string(basic_constraints.ca);
    if (!basic_constraints.path_len_constraint.empty()) {
        result += ", pathLenConstraint: " + basic_constraints.path_len_constraint;
    }
    return result;
}

std::string to_string(const Certificate &cert, const IndentationContext &indent_ctx)
{
    std::string result;
    result += "│ " + to_string(cert.tbs_certificate.subject) + "\n";
    result += "│ " + cert.tbs_certificate.validity.not_before + " .. " + cert.tbs_certificate.validity.not_after + "\n";
    result += "└──────────────────────────────────────────────────────────────────────────────\n";
    // TODO extensions
    for (auto it: cert.tbs_certificate.extensions.items) {
        if (it.first == oid_get_id("id-ce-basicConstraints")) {
            BasicConstraints basic_constraints = std::any_cast<BasicConstraints>(it.second.extn_value);
            //printf("basicConstraints: %s\n", to_string(basic_constraints).c_str());
        }
    }
    return result;
}
