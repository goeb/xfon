#include "data_model.h"

Array::~Array()
{
    for (auto i: items) delete i;
    items.clear();
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

Array::Array(const Array& other)
{
    *this = other;
}

Array& Array::operator=(const Array& other)
{
    if (this == &other) return *this;

    // Clean pre-existing value
    for (auto i: items) {
        delete i;
    }
    items.clear();
    for (auto i: other.items) {
        items.push_back(i->clone());
    }
    return *this;
}

Value *Array::clone() const
{
    Array *new_array = new Array();
    for (auto i: items) {
        new_array->items.push_back(i->clone());
    }
    return new_array;
}

Object::~Object()
{
    for (auto i: items) {
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

Object::Object(const Object &other)
{
    *this = other;
}

Object& Object::operator=(const Object &other)
{
    if (this == &other) return *this;

    // Clean pre-existing value
    for (auto i: items) {
        delete i.second;
    }
    items.clear();

    for (auto i: other.items) {
        items[i.first] = i.second->clone();
    }
    return *this;
}

Value *Object::clone() const
{
    Object *new_object = new Object();
    for (auto i: items) {
        new_object->items[i.first] = i.second->clone();
    }
    return new_object;
}

std::string GenericString::to_string() const
{
    return std::string(this->data(), this->size());
}

Value *Number::clone() const
{
    return new Number(this->to_string());
}

Value *String::clone() const
{
    return new String(this->to_string());
}

Value *Literal::clone() const
{
    return new Literal(this->to_string());
}

