#include "data_model.h"

Array::~Array()
{
    for (auto i: items) delete i;
}

std::string Array::to_string() const
{
    std::string result;
    for (auto const &i: items) {
        if (!result.empty()) result += ",";
        result += i->to_string();
    }
    result.insert(0, "[");
    result += "]";
    return result;
}

Object::~Object()
{
    for (auto i: items) {
        fprintf(stderr, "debug: ~Object(): delete i.second=%p\n", i.second);
        delete i.second;
    }
}

std::string Object::to_string() const
{
    std::string result;
    for (auto const &i: items) {
        if (!result.empty()) result += ",";
        result += i.first + ":" + i.second->to_string();
    }
    result.insert(0, "{");
    result += "}";
    return result;
}

std::string GenericString::to_string() const
{
    return std::string(this->data(), this->size());
}
