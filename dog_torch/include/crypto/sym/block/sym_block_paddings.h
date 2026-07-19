#pragma once
#include "export.h"

#include <iostream>

#include "sym_block_base.h"
#include "./paddings/ANSIX923.h"
#include "./paddings/ISO10126.h"
#include "./paddings/ISO7816_4.h"
#include "./paddings/PKCS7.h"
#include "./paddings/ZERO.h"

namespace dog_torch::crypto::sym::block::padding
{
	DOG_TORCH_API const std::vector<std::reference_wrapper<const Config>> get_all();
	DOG_TORCH_API std::unique_ptr<Padding> create(const std::string& name);
}

#define NS_ROOT(name) dog_torch__crypto__sym__block__##name
#define NS_PADDING(name) dog_torch__crypto__sym__block__padding__##name
#define CRYPTO_BASE(name) dog_torch__crypto__##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

extern "C"
{
	using NS_PADDING(ConfigVector) = std::vector<std::reference_wrapper<const NS_PADDING(Config)>>;

	C_API(NS_PADDING(ConfigVector)*)               NS_PADDING(get_all)                   ();
	C_API(void)                                    NS_PADDING(ConfigVector_delete)        (NS_PADDING(ConfigVector)** self);
	C_API(uint64_t)                                NS_PADDING(ConfigVector_size)          (const LVALUE(NS_PADDING(ConfigVector)) self);
	C_API(const LVALUE(NS_PADDING(Config)))        NS_PADDING(ConfigVector_at)            (LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(NS_PADDING(ConfigVector)) self, uint64_t index);

	C_API(NS_ROOT(Padding)*)                      NS_ROOT(Padding_create_c_str)         (const char* name);
	C_API(NS_ROOT(Padding)*)                      NS_ROOT(Padding_create_string)        (const LVALUE(UTILS(CppString)) name);
}
#undef NS_ROOT
#undef NS_PADDING
#undef CRYPTO_BASE
#undef SERIALIZE
#undef UTILS