#ifndef LOAD_H
#define LOAD_H

#include <string>
#include <vector>

#include "hierarchy.h"

int load_certificates(const std::list<std::string> &paths, std::vector<Certificate_with_links> &certificates);


#endif
