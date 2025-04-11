#ifndef OID_NAME_H
#define OID_NAME_H

#include <string>

std::string oid_get_name(const std::string &oid, bool shortname=false);
std::string oid_get_id(const std::string &name);


#endif // OID_NAME_H
