#include "certificate.h"


bool AttributeTypeAndValue::operator<(const AttributeTypeAndValue& other) const
{
    return (type < other.type) || ( (type == other.type) && (value < other.value) );
}

bool AttributeTypeAndValue::operator==(const AttributeTypeAndValue& other) const
{
    return (type == other.type) && (value == other.value);
}

