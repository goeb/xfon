
#include "journal.h"
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
    size_t indent_level = indent_ctx.lineage.size();
    LOGDEBUG("indent_level=%lu", indent_level);
    std::string indent_first_line;
    std::string indent_second_lines;
    std::string indent_last_line;
    if (indent_level) {
        for (size_t i=0; i<indent_level-1; i++) {
            indent_first_line += indent_ctx.lineage[i]?"   │":"    ";
        }
        indent_second_lines = indent_first_line;
        indent_last_line = indent_first_line;
        // do the last step, where first and second lines differ
        if (indent_ctx.lineage[indent_level-1]) {
            indent_first_line   += "   ├──┤ ";
            indent_second_lines += "   │  │ ";
            indent_last_line    += "   │  └─";
        } else {
            indent_first_line   += "   └──┤ ";
            indent_second_lines += "      │ ";
            indent_last_line    += "      └─";
        }
    } else {
        // This certificate has no parent
        indent_first_line   = "│ ";
        indent_second_lines = "│ ";
        indent_last_line    = "└─";
    }
    result += indent_first_line + to_string(cert.tbs_certificate.subject) + "\n";
    result += indent_second_lines + cert.tbs_certificate.validity.not_before + " .. " + cert.tbs_certificate.validity.not_after + "\n";
    if (indent_ctx.has_child) {
        result += indent_last_line + "─┬───────────────────────────────────────────────────────────────────────────\n";
    } else {
        result += indent_last_line + "─────────────────────────────────────────────────────────────────────────────\n";
    }

    // TODO extensions
    for (auto it: cert.tbs_certificate.extensions.items) {
        if (it.first == oid_get_id("id-ce-basicConstraints")) {
            BasicConstraints basic_constraints = std::any_cast<BasicConstraints>(it.second.extn_value);
            //printf("basicConstraints: %s\n", to_string(basic_constraints).c_str());
        }
    }
    return result;
}
