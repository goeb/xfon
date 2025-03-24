#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <map>
#include <string>

#include "data_model.h"

typedef std::string PropertyName;
typedef std::string PropertyValue;
typedef std::string ObjectIdentifier;

struct Extension {
    bool critical;
    Value *extn_value;
    Extension() : critical(false), extn_value(0) {}
    ~Extension() {
        if (extn_value) delete extn_value;
    }
    // Make it no copyable (because of the extn_value pointer that is not handled for copy)
    Extension(const Extension&) = delete;
    Extension& operator=(const Extension&) = delete;
};

class Certificate {
public:
    //Object *properties;
    Object properties;
    void *opaque;
};

#endif
