#include "crypto/crypto_base.h"

namespace NSROOT = dog_torch::crypto;

std::string NSROOT::get_type_name(ParamType type)
{
    switch (type)
    {
    case ParamType::Bool: return "Bool";
    case ParamType::UInt64: return "UInt64";
    case ParamType::String: return "String";
    case ParamType::Binary: return "Binary";
    case ParamType::Hash: return "Hash";
    }
    return "";
}

NSROOT::ParamInfo::ParamInfo(ParamType type_, const std::string& msg_)
    : type(type_), msg(msg_)
{}

#define NAMESPACE(name) dog_torch__crypto__##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

UTILS(CppString)* NAMESPACE(ParamType_name)(uint64_t type)
{
    using namespace dog_torch::crypto;
    using dog_torch::utils::to_c_style;
    return to_c_style(get_type_name(static_cast<ParamType>(type)));
}

NAMESPACE(Param)* NAMESPACE(Param_create_from_bool)(uint8_t value)
{
    return new NAMESPACE(Param)(value);
}

NAMESPACE(Param)* NAMESPACE(Param_create_from_uint64)(uint64_t value)
{
    return new NAMESPACE(Param)(value);
}

NAMESPACE(Param)* NAMESPACE(Param_create_from_c_str)(const char* value)
{
    return new NAMESPACE(Param)(value);
}

NAMESPACE(Param)* NAMESPACE(Param_create_from_string)(const LVALUE(UTILS(CppString)) value)
{
    using dog_torch::utils::to_string;
    return new NAMESPACE(Param)(to_string(value));
}

NAMESPACE(Param)* NAMESPACE(Param_create_from_binary)(const LVALUE(SERIALIZE(BinaryData)) value)
{
    return new NAMESPACE(Param)(*value);
}

void NAMESPACE(Param_delete)(NAMESPACE(Param)** self)
{
    DEFAULT_DESTOTY(self);
}

uint64_t NAMESPACE(Param_get_type)(const LVALUE(NAMESPACE(Param)) self)
{
    return self->index();
}

uint8_t NAMESPACE(Param_to_bool)(LVALUE(UTILS(CppResultSet))result_set, const LVALUE(NAMESPACE(Param)) self)
{
    try
    {
        return std::get<bool>(*self);
    }
    catch (const std::bad_variant_access& e)
    {
        using dog_torch::utils::CppResultSet_reset;
        CppResultSet_reset(result_set, -1, e.what());
        return 0;
    }
}

uint64_t NAMESPACE(Param_to_uint64)(LVALUE(UTILS(CppResultSet))result_set, const LVALUE(NAMESPACE(Param)) self)
{
    try
    {
        return std::get<uint64_t>(*self);
    }
    catch (const std::bad_variant_access& e)
    {
        using dog_torch::utils::CppResultSet_reset;
        CppResultSet_reset(result_set, -1, e.what());
        return 0;
    }
}

UTILS(CppString)* NAMESPACE(Param_to_string)(LVALUE(UTILS(CppResultSet))result_set, const LVALUE(NAMESPACE(Param)) self)
{
    using namespace dog_torch::utils;
    try
    {
        return to_c_style(std::get<std::string>(*self));
    }
    catch (const std::bad_variant_access& e)
    {
        CppResultSet_reset(result_set, -1, e.what());
        return nullptr;
    }
}

SERIALIZE(BinaryData)* NAMESPACE(Param_to_binary)(LVALUE(UTILS(CppResultSet))result_set, const LVALUE(NAMESPACE(Param)) self)
{
    using namespace dog_torch::utils;
    try
    {
        return new SERIALIZE(BinaryData)(std::get<SERIALIZE(BinaryData)>(*self));
    }
    catch (const std::bad_variant_access& e)
    {
        CppResultSet_reset(result_set, -1, e.what());
        return nullptr;
    }

}

NAMESPACE(ParamTreeMap)* NAMESPACE(ParamTreeMap_create)()
{
    return new NAMESPACE(ParamTreeMap)();
}

NAMESPACE(ParamTreeMap)* NAMESPACE(ParamTreeMap_create_from_hash)(const LVALUE(NAMESPACE(ParamHashMap)) hash_map)
{
    auto map = new NAMESPACE(ParamTreeMap)();
    for (auto& [key, value] : *hash_map)
    {
        map->emplace(key, value);
    }
    return map;
}

void NAMESPACE(ParamTreeMap_delete)(NAMESPACE(ParamTreeMap)** self)
{
    DEFAULT_DESTOTY(self);
}

LVALUE(NAMESPACE(Param)) NAMESPACE(ParamTreeMap_at_c_str)(LVALUE(UTILS(CppResultSet))result_set, LVALUE(NAMESPACE(ParamTreeMap))self, const char* key)
{
    using dog_torch::utils::CppResultSet_reset;
    if (self == nullptr)
    {
        CppResultSet_reset(result_set, -1, "self is null");
        return nullptr;
    }
    if (key == nullptr)
    {
        CppResultSet_reset(result_set, -2, "key is null");
        return nullptr;
    }
    if (!self->contains(key))
    {
        CppResultSet_reset(result_set, -3, "key not found");
        return nullptr;
    }
    return &(self->at(key));
}

LVALUE(NAMESPACE(Param)) NAMESPACE(ParamTreeMap_at_string)(LVALUE(UTILS(CppResultSet))result_set, LVALUE(NAMESPACE(ParamTreeMap))self, const LVALUE(UTILS(CppString))key)
{
    using dog_torch::utils::CppResultSet_reset;
    using dog_torch::utils::to_string;
    if (self == nullptr)
    {
        CppResultSet_reset(result_set, -1, "self is null");
        return nullptr;
    }
    if (key == nullptr || key->size == 0 || key->str_ptr == nullptr)
    {
        CppResultSet_reset(result_set, -2, "key is null or empty");
        return nullptr;
    }
    auto key_ = to_string(key);
    if (!self->contains(key_))
    {
        CppResultSet_reset(result_set, -3, "key not found");
        return nullptr;
    }
    return &(self->at(key_));
}

NAMESPACE(ParamHashMap)* NAMESPACE(ParamHashMap_create)()
{
    return new NAMESPACE(ParamHashMap)();
}

NAMESPACE(ParamHashMap)* NAMESPACE(ParamHashMap_create_from_tree)(const LVALUE(NAMESPACE(ParamTreeMap))tree_map)
{
    auto map = new NAMESPACE(ParamHashMap)();
    for (auto& [key, value] : *tree_map)
    {
        map->emplace(key, value);
    }
    return map;
}

void NAMESPACE(ParamHashMap_delete)(NAMESPACE(ParamHashMap)** self)
{
    DEFAULT_DESTOTY(self);
}

LVALUE(NAMESPACE(Param)) NAMESPACE(ParamHashMap_at_c_str)(LVALUE(UTILS(CppResultSet))result_set, LVALUE(NAMESPACE(ParamHashMap))self, const char* key)
{
    using dog_torch::utils::CppResultSet_reset;
    if (self == nullptr)
    {
        CppResultSet_reset(result_set, -1, "self is null");
        return nullptr;
    }
    if (key == nullptr)
    {
        CppResultSet_reset(result_set, -2, "key is null");
        return nullptr;
    }
    if (!self->contains(key))
    {
        CppResultSet_reset(result_set, -3, "key not found");
        return nullptr;
    }
    return &(self->at(key));
}

LVALUE(NAMESPACE(Param)) NAMESPACE(ParamHashMap_at_string)(LVALUE(UTILS(CppResultSet))result_set, LVALUE(NAMESPACE(ParamHashMap))self, const LVALUE(UTILS(CppString))key)
{
    using dog_torch::utils::CppResultSet_reset;
    using dog_torch::utils::to_string;
    if (self == nullptr)
    {
        CppResultSet_reset(result_set, -1, "self is null");
        return nullptr;
    }
    if (key == nullptr || key->size == 0 || key->str_ptr == nullptr)
    {
        CppResultSet_reset(result_set, -2, "key is null or empty");
        return nullptr;
    }
    auto key_ = to_string(key);
    if (!self->contains(key_))
    {
        CppResultSet_reset(result_set, -3, "key not found");
        return nullptr;
    }
    return &(self->at(key_));
}

void NAMESPACE(ParamInfoTreeMap_delete)(NAMESPACE(ParamInfoTreeMap)** self)
{
    DEFAULT_DESTOTY(self);
}

uint64_t NAMESPACE(ParamInfoTreeMap_at_c_str)(LVALUE(UTILS(CppResultSet))result_set, LVALUE(NAMESPACE(ParamInfoTreeMap))self, const char* key)
{
    using dog_torch::utils::CppResultSet_reset;
    if (self == nullptr)
    {
        CppResultSet_reset(result_set, -1, "self is null");
        return 0;
    }
    if (key == nullptr)
    {
        CppResultSet_reset(result_set, -2, "key is null");
        return 0;
    }
    if (!self->contains(key))
    {
        CppResultSet_reset(result_set, -3, "key not found");
        return 0;
    }
    return static_cast<uint64_t>(self->at(key).type);
}

uint64_t NAMESPACE(ParamInfoTreeMap_at_string)(LVALUE(UTILS(CppResultSet))result_set, LVALUE(NAMESPACE(ParamInfoTreeMap))self, const LVALUE(UTILS(CppString))key)
{
    using dog_torch::utils::CppResultSet_reset;
    using dog_torch::utils::to_string;
    if (self == nullptr)
    {
        CppResultSet_reset(result_set, -1, "self is null");
        return 0;
    }
    if (key == nullptr || key->size == 0 || key->str_ptr == nullptr)
    {
        CppResultSet_reset(result_set, -2, "key is null or empty");
        return 0;
    }
    auto key_ = to_string(key);
    if (!self->contains(key_))
    {
        CppResultSet_reset(result_set, -3, "key not found");
        return 0;
    }
    return static_cast<uint64_t>(self->at(key_).type);
}

#undef NAMESPACE
#undef SERIALIZE
#undef UTILS