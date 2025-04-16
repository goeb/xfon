#ifndef RENDER_TEXT_H
#define RENDER_TEXT_H

#include <string>

#include "certificate.h"

std::string to_string(const Name &name);
std::string to_string(bool);
std::string to_string(const BasicConstraints &);

#endif // RENDER_TEXT_H
