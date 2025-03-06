#ifndef DATA_MODEL_H
#define DATA_MODEL_H

#include <list>
#include <map>
#include <string>

enum ValueType {
    V_ARRAY,
    V_NUMBER,
    V_OBJECT,
    V_STRING,
    V_LITERAL
};

/**
 * @brief The Value class
 *
 * Abstract class used for having a composite value
 * containing child composite values.
 */
class Value {
public:
    virtual enum ValueType get_type() const = 0;
    virtual std::string to_string() const = 0;
    virtual ~Value() {}
};

/**
 * @brief Array of values [ value, ... ]
 */
class Array : public Value {
public:
    inline enum ValueType get_type() const { return V_ARRAY; }
    std::list<Value*> items;
    ~Array();
    std::string to_string() const;
};

/**
 * @brief Hash table of values { key: value, ... }
 * "Object" here refers to the JSON definition of "Object".
 */
class Object : public Value {
public:
    enum ValueType get_type() const { return V_OBJECT; }
    std::map<std::string, Value*> items;
    ~Object();
    std::string to_string() const;
};

class GenericString : public Value, std::string {
public:
    virtual enum ValueType get_type() const = 0;
    GenericString(const std::string &val) : std::string(val) {}
    virtual std::string to_string() const;
};

class Number : public GenericString {
public:
    inline enum ValueType get_type() const { return V_NUMBER; }
    Number(const std::string &val) : GenericString(val) {}
};

class String : public GenericString {
public:
    inline enum ValueType get_type() const { return V_STRING; }
    String(const std::string &val) : GenericString(val) {}
};

class Literal : public GenericString {
public:
    Literal(const std::string &val) : GenericString(val) {}
    enum ValueType get_type() const { return V_LITERAL; }
};

#endif
