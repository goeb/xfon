#ifndef HIERARCHY_H
#define HIERARCHY_H

#include "certificate.h"

struct Certificate_with_links : public Certificate {
    std::list<Certificate_with_links*> parents;
    std::list<Certificate_with_links*> children;
    Certificate_with_links(const Certificate &cert):  Certificate(cert) {}
};

bool is_self_signed(const Certificate &cert);
bool is_issuer(const Certificate &cert_issuer, const Certificate &cert_child);

std::list<Certificate_with_links> compute_hierarchy(const std::list<Certificate> &certificates);

#endif
