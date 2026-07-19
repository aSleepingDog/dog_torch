#include "crypto/hash/hash_algorithms.h"

namespace NSROOT = dog_torch::crypto::hash::algorithm;

std::vector<std::reference_wrapper<const NSROOT::Config>> NSROOT::get_all()
{
    return {
        std::cref(SHA2::allowed_config()),
        std::cref(SM3::allowed_config()),
        std::cref(BLAKE2::allowed_config())
    };
}

std::unique_ptr<NSROOT::Algorithm> NSROOT::create(const std::string& name, uint64_t effective, const std::unordered_map<std::string, Param>& params)
{
    if (name == SHA2::allowed_config().name)
    {
        return std::make_unique<SHA2>(effective);
    }
    else if (name == SM3::allowed_config().name)
    {
        return std::make_unique<SM3>();
    }
    else if (name == BLAKE2::allowed_config().name)
    {
        uint8_t out_size = 0;
        BinaryData key, salt, person;
        if (params.find("out_size") != params.end() && params.at("out_size").index() == (size_t)ParamType::UInt64)
        {
            out_size = static_cast<uint8_t>(std::get<uint64_t>(params.at("out_size")));
        }
        if (params.find("key") != params.end() && params.at("key").index() == (size_t)ParamType::Binary)
        {
            key = std::get<BinaryData>(params.at("key"));
        }
        if (params.find("salt") != params.end() && params.at("salt").index() == (size_t)ParamType::Binary)
        {
            salt = std::get<BinaryData>(params.at("salt"));
        }
        if (params.find("person") != params.end() && params.at("personalization").index() == (size_t)ParamType::Binary)
        {
            person = std::get<BinaryData>(params.at("personalization"));
        }
        return std::make_unique<BLAKE2>(effective, out_size, key, salt, person);
    }
    return nullptr;
}


#define NAMESPACE(name) dog_torch__crypto__hash__algorithm__##name
#define CRYPTO_HASH_BASE(name) dog_torch__crypto__hash__##name
#define CRYPTO_BASE(name) dog_torch__crypto__##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

NAMESPACE(ConfigVector)* NAMESPACE(get_all)()
{
    return new NAMESPACE(ConfigVector){ dog_torch::crypto::hash::algorithm::get_all() };
}
void NAMESPACE(ConfigVector_delete)(NAMESPACE(ConfigVector)** self)
{
    DEFAULT_DESTOTY(self);
}

uint64_t NAMESPACE(ConfigVector_size)(const LVALUE(NAMESPACE(ConfigVector))self)
{
    if (self == nullptr) return 0;
    return self->size();
}
const LVALUE(CRYPTO_HASH_BASE(Config)) NAMESPACE(ConfigVector_at)(LVALUE(UTILS(CppResultSet))result_set, const LVALUE(NAMESPACE(ConfigVector))self, uint64_t index)
{
    using dog_torch::utils::CppResultSet_reset;
    if (self == nullptr)
    {
        CppResultSet_reset(result_set, -1, "self is null");
        return nullptr;
    }
    if (index >= self->size())
    {
        CppResultSet_reset(result_set, -2, "index out of range");
        return nullptr;
    }
    return &(self->at(index).get());
}


CRYPTO_HASH_BASE(Algorithm)* CRYPTO_HASH_BASE(Algorithm_create_c_str)(const char* name, uint64_t effective, const LVALUE(CRYPTO_BASE(ParamHashMap))map)
{
    auto ualg = NSROOT::create(name, effective, *map);
    if (ualg == nullptr) return nullptr;
    auto alg = ualg.release();
    return alg;
}
CRYPTO_HASH_BASE(Algorithm)* CRYPTO_HASH_BASE(Algorithm_create_string)(const LVALUE(UTILS(CppString))name, uint64_t effective, const LVALUE(CRYPTO_BASE(ParamHashMap))map)
{
    using dog_torch::utils::to_string;
    auto ualg = NSROOT::create(to_string(name), effective, *map);
    if (ualg == nullptr) return nullptr;
    auto alg = ualg.release();
    return alg;
}
#undef NAMESPACE
#undef CRYPTO_HASH_BASE
#undef CRYPTO_BASE
#undef SERIALIZE
#undef UTILS