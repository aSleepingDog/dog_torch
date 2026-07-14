#pragma once
#include "export.h"

#include <string>
#include <variant>
#include <filesystem>

#include "serialize/serialize.h"

namespace dog_torch::crypto
{
	using dog_torch::serialize::BinaryData;
	using Param = std::variant<bool, uint64_t, std::string, BinaryData>;
	enum class ParamType : uint64_t
	{
		Bool = 0,
		UInt64 = 1,
		String = 2,
		Binary = 3
	};
	std::string get_type_name(ParamType type);
}

#define NAMESPACE(name) dog_torch__crypto__##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

extern "C"
{
	using NAMESPACE(ParamType) = dog_torch::crypto::ParamType;
	using NAMESPACE(Param) = dog_torch::crypto::Param;
	using NAMESPACE(ParamTypeTreeMap) = std::map<std::string, NAMESPACE(ParamType)>;
	using NAMESPACE(ParamTreeMap) = std::map<std::string, NAMESPACE(Param)>;
	using NAMESPACE(ParamHashMap) = std::unordered_map<std::string, NAMESPACE(Param)>;
	//ParamType
	C_API(UTILS(CppString)*)         NAMESPACE(ParamType_name)                    (uint64_t type);
	//Param
	C_API(NAMESPACE(Param)*)         NAMESPACE(Param_create_from_bool)            (uint8_t value);
	C_API(NAMESPACE(Param)*)         NAMESPACE(Param_create_from_uint64)          (uint64_t value);
	C_API(NAMESPACE(Param)*)         NAMESPACE(Param_create_from_c_str)           (const char* value);
	C_API(NAMESPACE(Param)*)         NAMESPACE(Param_create_from_string)          (const LVALUE(UTILS(CppString)) value);
	C_API(NAMESPACE(Param)*)         NAMESPACE(Param_create_from_binary)          (const LVALUE(SERIALIZE(BinaryData)) value);
	C_API(void)                      NAMESPACE(Param_delete)                      (NAMESPACE(Param)* self);

	C_API(uint64_t)                  NAMESPACE(Param_get_type)                    (const LVALUE(NAMESPACE(Param)) self);
	C_API(uint8_t)                   NAMESPACE(Param_to_bool)                     (LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(NAMESPACE(Param)) self);
	C_API(uint64_t)                  NAMESPACE(Param_to_uint64)                   (LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(NAMESPACE(Param)) self);
	C_API(UTILS(CppString)*)         NAMESPACE(Param_to_string)                   (LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(NAMESPACE(Param)) self);
	C_API(SERIALIZE(BinaryData)*)    NAMESPACE(Param_to_binary)                   (LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(NAMESPACE(Param)) self);
	//ParamTreeMap
	C_API(NAMESPACE(ParamTreeMap)*)  NAMESPACE(ParamTreeMap_create)               ();
	C_API(NAMESPACE(ParamTreeMap)*)  NAMESPACE(ParamTreeMap_create_from_hash)     (const LVALUE(NAMESPACE(ParamHashMap)) hash_map);
	C_API(void)                      NAMESPACE(ParamTreeMap_delete)               (NAMESPACE(ParamTreeMap)* self);

	C_API(LVALUE(NAMESPACE(Param)))  NAMESPACE(ParamTreeMap_at_c_str)             (LVALUE(UTILS(CppResultSet)) result_set, LVALUE(NAMESPACE(ParamTreeMap)) self, const char* key);
	C_API(LVALUE(NAMESPACE(Param)))  NAMESPACE(ParamTreeMap_at_string)            (LVALUE(UTILS(CppResultSet)) result_set, LVALUE(NAMESPACE(ParamTreeMap)) self, const LVALUE(UTILS(CppString)) key);
	//ParamHashMap
	C_API(NAMESPACE(ParamHashMap)*)  NAMESPACE(ParamHashMap_create)               ();
	C_API(NAMESPACE(ParamHashMap)*)  NAMESPACE(ParamHashMap_create_from_tree)     (const LVALUE(NAMESPACE(ParamTreeMap)) tree_map);
	C_API(void)                      NAMESPACE(ParamHashMap_delete)               (NAMESPACE(ParamHashMap)* self);

	C_API(LVALUE(NAMESPACE(Param)))  NAMESPACE(ParamHashMap_at_c_str)             (LVALUE(UTILS(CppResultSet)) result_set, LVALUE(NAMESPACE(ParamHashMap)) self, const char* key);
	C_API(LVALUE(NAMESPACE(Param)))  NAMESPACE(ParamHashMap_at_string)            (LVALUE(UTILS(CppResultSet)) result_set, LVALUE(NAMESPACE(ParamHashMap)) self, const LVALUE(UTILS(CppString)) key);
	//ParamTypeTreeMap
	C_API(void)                      NAMESPACE(ParamTypeTreeMap_delete)           (NAMESPACE(ParamTypeTreeMap)* self);

	C_API(uint64_t)                  NAMESPACE(ParamTypeTreeMap_at_c_str)         (LVALUE(UTILS(CppResultSet)) result_set, LVALUE(NAMESPACE(ParamTypeTreeMap)) self, const char* key);
	C_API(uint64_t)                  NAMESPACE(ParamTypeTreeMap_at_string)        (LVALUE(UTILS(CppResultSet)) result_set, LVALUE(NAMESPACE(ParamTypeTreeMap)) self, const LVALUE(UTILS(CppString)) key);
}

#undef NAMESPACE
#undef SERIALIZE
#undef UTILS