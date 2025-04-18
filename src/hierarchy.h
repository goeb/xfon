#ifndef HIERARCHY_H
#define HIERARCHY_H

#include <vector>

#include "certificate.h"

struct Certificate_with_links : public Certificate {
    std::list<Certificate_with_links*> parents;
    std::list<Certificate_with_links*> children;
    Certificate_with_links(const Certificate &cert):  Certificate(cert) {}
};

std::vector<Certificate_with_links> compute_hierarchy(const std::vector<Certificate> &certificates);

#endif
