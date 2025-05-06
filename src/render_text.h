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

void print_tree(const std::vector<Certificate_with_links> &certificates, bool minimal=false);

void print_cert(const Certificate_with_links &certificate, bool single);

#endif // RENDER_TEXT_H
