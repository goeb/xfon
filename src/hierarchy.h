#ifndef HIERARCHY_H
#define HIERARCHY_H

#include <vector>

#include "certificate.h"

struct Certificate_with_links : public Certificate {
    std::string filename;
    size_t index_in_file;
    std::list<Certificate_with_links*> parents;
    std::list<Certificate_with_links*> children;
    Certificate_with_links(const Certificate &cert):  Certificate(cert) {}
};

void compute_hierarchy(std::vector<Certificate_with_links> &certificates);

#endif
