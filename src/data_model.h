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

class Value {
public:
    virtual enum ValueType get_type() const = 0;
    virtual std::string to_string() const = 0;
    virtual ~Value() {}
};

class Array : public Value {
public:
    enum ValueType get_type() const { return V_ARRAY; }
    std::list<Value*> items;
    ~Array() { for (auto i: items) delete i; }
    std::string to_string() const {
        std::string result;
        for (auto const &i: items) {
            if (!result.empty()) result += ",";
            result += i->to_string();
        }
        result.insert(0, "[");
        result += "]";
        return result;
    }
};

class Number : public Value, std::string {
public:
    Number(const std::string &val) : std::string(val) {}
    enum ValueType get_type() const { return V_NUMBER; }
    std::string to_string() const { return std::string(this->data(), this->size()); }
};

class Object : public Value {
public:
    enum ValueType get_type() const { return V_OBJECT; }
    std::map<std::string, Value*> items;
    ~Object() { for (auto i: items) {
            fprintf(stderr, "debug: ~Object(): delete i.second=%p\n", i.second);
            delete i.second; }
    }
    std::string to_string() const {
        std::string result;
        for (auto const &i: items) {
            if (!result.empty()) result += ",";
            result += i.first + ":" + i.second->to_string();
        }
        result.insert(0, "{");
        result += "}";
        return result;
    }
};

class String : public Value {
private:
    std::string value;
public:
    String(const std::string &val) : value(val) {}
    enum ValueType get_type() const { return V_STRING; }
    std::string to_string() const { return std::string(this->value.data(), this->value.size()); }
};

class Literal : public Value, std::string {
public:
    Literal(const std::string &val) : std::string(val) {}
    enum ValueType get_type() const { return V_LITERAL; }
    std::string to_string() const { return std::string(this->data(), this->size()); }
};

#if 0
int main()
{
    Object root;

    root.items["#"] = new Number("-123");
    root.items["x"] = new Literal("null");
    root.items["children"] = new Array();
}
#endif

#endif
