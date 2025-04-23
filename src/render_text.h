#ifndef RENDER_TEXT_H
#define RENDER_TEXT_H

#include <string>
#include <vector>

#include "certificate.h"
#include "hierarchy.h"

struct IndentationContext {
    std::vector<bool> lineage; // indicates the indentation level and lines that must be drawn before
};

std::string to_string(const Name &name);
std::string to_string(bool);
std::string to_string(const BasicConstraints &);
std::string to_string(const Certificate_with_links &cert, const IndentationContext &indent_ctx=IndentationContext());

void print_tree(const std::vector<Certificate_with_links> &certificates);

#endif // RENDER_TEXT_H
