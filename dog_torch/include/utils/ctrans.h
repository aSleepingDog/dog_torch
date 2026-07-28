#pragma once
#include "export.h"

#include <cstdio>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <string>
#include <filesystem>
#include "exception.h"

#define NAMESPACE(name) dog_torch__utils__##name
#define LVALUE(type)            type* const
#define DEFAULT_DESTOTY(ptr)\
if(ptr == nullptr || (*ptr)==nullptr) return;\
delete (*ptr);\
(*ptr) = nullptr

struct NAMESPACE(CppString)
{
	uint64_t size;
	char* str_ptr;
};

struct NAMESPACE(CppUint64Array)
{
	uint64_t size;
	uint64_t* data;
};

struct NAMESPACE(CppResultSet)
{
	int64_t code;
	NAMESPACE(CppString)* msg;
};

namespace dog_torch::utils
{
	CPP_API NAMESPACE(CppString)* to_c_style(const std::string& cppstr);
	CPP_API std::string to_string(const LVALUE(NAMESPACE(CppString)) cstr);
	CPP_API NAMESPACE(CppUint64Array)* to_c_style(const std::vector<uint64_t>& cppvec);

	CPP_API void CppResultSet_reset(LVALUE(NAMESPACE(CppResultSet)) self, int64_t code, const std::string& msg);
}

extern "C"
{
	C_API(NAMESPACE(CppString)*)               NAMESPACE(CppString_create_from_c_str)       (const char* str);
	C_API(NAMESPACE(CppString)*)               NAMESPACE(CppString_create_from_c_str_size)  (const char* str, uint64_t size);
	C_API(const char*)                         NAMESPACE(CppString_get_c_str)               (const LVALUE(NAMESPACE(CppString)) target);
	C_API(void)                                NAMESPACE(CppString_delete)                  (NAMESPACE(CppString)** target);
	
	C_API(NAMESPACE(CppResultSet)*)            NAMESPACE(CppResultSet_create)               ();
	C_API(void)                                NAMESPACE(CppResultSet_delete)               (NAMESPACE(CppResultSet)** self);

	C_API(const char*)                         NAMESPACE(CppResultSet_get_msg)              (const LVALUE(NAMESPACE(CppResultSet)) self);
	C_API(int64_t)                             NAMESPACE(CppResultSet_get_code)             (const LVALUE(NAMESPACE(CppResultSet)) self);

	C_API(uint64_t)                            NAMESPACE(CppUint64Array_at)                 (LVALUE(NAMESPACE(CppResultSet)) result, const LVALUE(NAMESPACE(CppUint64Array)) target, uint64_t index);
	C_API(void)                                NAMESPACE(CppUint64Array_delete)             (NAMESPACE(CppUint64Array)** target);
}

#undef NAMESPACE