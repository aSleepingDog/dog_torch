#pragma once
#include "export.h"

#include <iostream>

#include "crypto/crypto_base.h"
#include "hash_base.h"
#include "./algorithms/SHA2.h"
#include "./algorithms/SM3.h"
#include "./algorithms/BLAKE.h"

namespace dog_torch::crypto::hash::algorithm
{
	DOG_TORCH_API std::array<std::reference_wrapper<const Config>,3> get_all();
	DOG_TORCH_API std::unique_ptr<Algorithm> create(const std::string& name, uint64_t effective, const std::unordered_map<std::string, Param>& params);
}

#define NAMESPACE(name) dog_torch__crypto__hash__algorithm__##name
#define CRYPTO_HASH_BASE(name) dog_torch__crypto__hash__##name
#define CRYPTO_BASE(name) dog_torch__crypto__##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

extern "C"
{
	using NAMESPACE(ConfigArray) = std::array<std::reference_wrapper<const CRYPTO_HASH_BASE(Config)>, 3>;

	C_API(NAMESPACE(ConfigArray)*)                NAMESPACE(get_all)                          ();
	C_API(void)                                   NAMESPACE(ConfigArray_delete)               (NAMESPACE(ConfigArray)** self);
	C_API(uint64_t)                               NAMESPACE(ConfigArray_size)                 (const LVALUE(NAMESPACE(ConfigArray)) self);
	C_API(const LVALUE(CRYPTO_HASH_BASE(Config))) NAMESPACE(ConfigArray_at)                   (LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(NAMESPACE(ConfigArray)) self, uint64_t index);

	C_API(CRYPTO_HASH_BASE(Algorithm)*)           CRYPTO_HASH_BASE(Algorithm_create_c_str)    (const char* name, uint64_t effective, const LVALUE(CRYPTO_BASE(ParamHashMap)) map);
	C_API(CRYPTO_HASH_BASE(Algorithm)*)           CRYPTO_HASH_BASE(Algorithm_create_string)   (const LVALUE(UTILS(CppString)) name, uint64_t effective, const LVALUE(CRYPTO_BASE(ParamHashMap)) map);
}

#undef NAMESPACE
#undef CRYPTO_HASH_BASE
#undef CRYPTO_BASE
#undef SERIALIZE
#undef UTILS