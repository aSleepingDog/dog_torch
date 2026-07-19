#pragma once
#include "export.h"

#include <iostream>

#include "utils/ctrans.h"
#include "crypto/crypto_base.h"
#include "sym_block_base.h"
#include "crypto/sym/block/modes/ECB.h"
#include "crypto/sym/block/modes/CBC.h"
#include "crypto/sym/block/modes/PCBC.h"
#include "crypto/sym/block/modes/CFB.h"
#include "crypto/sym/block/modes/OFB.h"
#include "crypto/sym/block/modes/CTR.h"
#include "crypto/sym/block/modes/GCM.h"

namespace dog_torch::crypto::sym::block::mode
{
	DOG_TORCH_API const std::vector<std::reference_wrapper<const Config>> get_all();
	DOG_TORCH_API std::unique_ptr<Mode> create(const std::string& name, const padding::Padding& padding, const std::unordered_map<std::string, Param>& params);
}

#define NS_ROOT(name) dog_torch__crypto__sym__block__##name
#define NS_MODE(name) dog_torch__crypto__sym__block__mode__##name
#define CRYPTO_BASE(name) dog_torch__crypto__##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

extern "C"
{
	using NS_MODE(ConfigVector) = std::vector<std::reference_wrapper<const NS_MODE(Config)>>;

	C_API(NS_MODE(ConfigVector)*)            NS_MODE(get_all)                   ();
	C_API(void)                              NS_MODE(ConfigVector_delete)        (NS_MODE(ConfigVector)** self);
	C_API(uint64_t)                          NS_MODE(ConfigVector_size)          (const LVALUE(NS_MODE(ConfigVector)) self);
	C_API(const LVALUE(NS_MODE(Config)))     NS_MODE(ConfigVector_at)            (LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(NS_MODE(ConfigVector)) self, uint64_t index);

	C_API(NS_ROOT(Mode)*)                   NS_ROOT(Mode_create_c_str)         (const char* name, const LVALUE(NS_ROOT(Padding)) padding, const LVALUE(CRYPTO_BASE(ParamHashMap)) params);
	C_API(NS_ROOT(Mode)*)                   NS_ROOT(Mode_create_string)        (const LVALUE(UTILS(CppString)) name, const LVALUE(NS_ROOT(Padding)) padding, const LVALUE(CRYPTO_BASE(ParamHashMap)) params);
}
#undef NS_ROOT
#undef NS_PADDING
#undef CRYPTO_BASE
#undef SERIALIZE
#undef UTILS