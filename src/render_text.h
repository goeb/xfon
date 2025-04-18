#ifndef RENDER_TEXT_H
#define RENDER_TEXT_H

#include <string>
#include <vector>

#include "certificate.h"

struct IndentationContext {
    std::vector<bool> lineage; // indicates the indentation level and lines that must be drawn before
    bool has_child;
};

std::string to_string(const Name &name);
std::string to_string(bool);
std::string to_string(const BasicConstraints &);
std::string to_string(const Certificate &cert, const IndentationContext &indent_ctx=IndentationContext());

#endif // RENDER_TEXT_H
