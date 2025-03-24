#ifndef HIERARCHY_H
#define HIERARCHY_H

#include "certificate.h"

bool is_self_signed(const Certificate &cert);
bool is_issuer(const Certificate &cert_issuer, const Certificate &cert_child);

#endif
