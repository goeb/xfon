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
    virtual Value *clone() const = 0;
};

/**
 * @brief Array of values [ value, ... ]
 */
class Array : public Value {
private:
    std::list<Value*> items;
public:
    inline enum ValueType get_type() const { return V_ARRAY; }
    Array() {}
    ~Array();
    std::string to_string() const;
    Array(const Array &other);
    Array& operator=(const Array &other);
    void push_back(Value *value);
    Value *clone() const;
};

/**
 * @brief Hash table of values { key: value, ... }
 * "Object" here refers to the JSON definition of "Object".
 */
class Object : public Value {
private:
    std::map<std::string, Value*> items;
public:
    enum ValueType get_type() const { return V_OBJECT; }
    Object() {}
    ~Object();
    std::string to_string() const;
    Object(const Object &other);
    Object& operator=(const Object &other);
    void insert(const std::string &key, Value *value);
    Value *clone() const;
};

class GenericString : public Value, std::string {
public:
    GenericString(const std::string &val) : std::string(val) {}
    virtual std::string to_string() const;
};

class Number : public GenericString {
public:
    inline enum ValueType get_type() const { return V_NUMBER; }
    Number(const std::string &val) : GenericString(val) {}
    Value *clone() const;
};

class String : public GenericString {
public:
    inline enum ValueType get_type() const { return V_STRING; }
    String(const std::string &val) : GenericString(val) {}
    Value *clone() const;
};

class Literal : public GenericString {
public:
    Literal(const std::string &val) : GenericString(val) {}
    enum ValueType get_type() const { return V_LITERAL; }
    Value *clone() const;
};

#endif
