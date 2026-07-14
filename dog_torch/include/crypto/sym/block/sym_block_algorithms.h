#pragma once
#include "export.h"

#include <iostream>

#include "sym_block_base.h"
#include "./algorithms/Rijndael.h"
#include "./algorithms/SM4.h"
#include "./algorithms/camellia.h"
#include "./algorithms/Twofish.h"

namespace dog_torch::crypto::sym::block::algorithm
{
	DOG_TORCH_API const std::array<std::reference_wrapper<const Config>, 4> get_all();
	DOG_TORCH_API std::unique_ptr<Algorithm> create(const std::string& name, uint64_t block_size, uint64_t key_size);
}

#define NS_ROOT(name) dog_torch__crypto__sym__block__##name
#define NS_ALG(name) dog_torch__crypto__sym__block__algorithm__##name
#define CRYPTO_BASE(name) dog_torch__crypto__##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

extern "C"
{
	using NS_ALG(ConfigArray) = std::array<std::reference_wrapper<const NS_ALG(Config)>, 4>;

	C_API(NS_ALG(ConfigArray)*)               NS_ALG(get_all)                   ();
	C_API(void)                               NS_ALG(ConfigArray_delete)        (NS_ALG(ConfigArray)** self);
	C_API(uint64_t)                           NS_ALG(ConfigArray_size)          (const LVALUE(NS_ALG(ConfigArray)) self);
	C_API(const LVALUE(NS_ALG(Config)))       NS_ALG(ConfigArray_at)            (LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(NS_ALG(ConfigArray)) self, uint64_t index);

	C_API(NS_ROOT(Algorithm)*)                NS_ROOT(Algorithm_create_c_str)   (const char* name, uint64_t block_size, uint64_t key_size);
	C_API(NS_ROOT(Algorithm)*)                NS_ROOT(Algorithm_create_string)  (const LVALUE(UTILS(CppString)) name, uint64_t block_size, uint64_t key_size);
}
#undef NS_ROOT
#undef NS_ALG
#undef CRYPTO_BASE
#undef SERIALIZE
#undef UTILS
