#include <stdio.h>

#include "data_model.h"

int main()
{
	Object obj;
	obj.insert("a", new Number("123"));
	obj.insert("b", new Number("456"));
	obj.insert("b", new Number("456"));
	obj.insert("c", new Literal("true"));

	printf("obj=%s\n", obj.to_string().c_str());

	Object *obj2 = new Object();
	*obj2 = obj;
	obj2->insert("d", new String("xxx"));

	obj2->insert("e", obj.clone());

	printf("obj2=%s\n", obj2->to_string().c_str());


	Array array1;
	array1.push_back(new String("yyy"));
	array1.push_back(obj2->clone());

	printf("array1=%s\n", array1.to_string().c_str());
	delete obj2;

	Array *array2 = new Array();
    *array2	= array1;

	array2->push_back(new Literal("undefined"));
	printf("array2=%s\n", array2->to_string().c_str());
	delete array2;
}
