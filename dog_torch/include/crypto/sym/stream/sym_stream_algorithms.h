#pragma once
#include "export.h"

#include <iostream>

#include "sym_stream_base.h"
#include "./algorithms/ChaCha.h"

namespace dog_torch::crypto::sym::stream::algorithm
{
	CPP_API const std::vector<std::reference_wrapper<const Config>> get_all();
	CPP_API std::unique_ptr<Algorithm> create(const std::string& name, uint64_t effective, uint64_t key_size);
}

#define NS_ROOT(name) dog_torch__crypto__sym__stream__##name
#define NS_ALG(name) dog_torch__crypto__sym__stream__algorithm__##name
#define CRYPTO_BASE(name) dog_torch__crypto__##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

extern "C"
{
	using NS_ALG(ConfigVector) = std::vector<std::reference_wrapper<const NS_ALG(Config)>>;

	C_API(NS_ALG(ConfigVector)*)               NS_ALG(get_all)                    ();
	C_API(void)                                NS_ALG(ConfigVector_delete)        (NS_ALG(ConfigVector)** self);
	C_API(uint64_t)                            NS_ALG(ConfigVector_size)          (const LVALUE(NS_ALG(ConfigVector)) self);
	C_API(const LVALUE(NS_ALG(Config)))        NS_ALG(ConfigVector_at)            (LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(NS_ALG(ConfigVector)) self, uint64_t index);

	C_API(NS_ROOT(Algorithm)*)                NS_ROOT(Algorithm_create_c_str)   (const char* name, uint64_t block_size, uint64_t key_size);
	C_API(NS_ROOT(Algorithm)*)                NS_ROOT(Algorithm_create_string)  (const LVALUE(UTILS(CppString)) name, uint64_t block_size, uint64_t key_size);
}
#undef NS_ROOT
#undef NS_ALG
#undef CRYPTO_BASE
#undef SERIALIZE
#undef UTILS