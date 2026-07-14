#include "crypto/sym/block/sym_block_algorithms.h"

namespace NSROOT = dog_torch::crypto::sym::block::algorithm;

const std::array<std::reference_wrapper<const NSROOT::Config>, 4> NSROOT::get_all()
{
    return {
        std::cref(AES::allowed_config()),
        std::cref(SM4::allowed_config()),
        std::cref(Camellia::allowed_config()),
        std::cref(Twofish::allowed_config())
    };
}
std::unique_ptr<NSROOT::Algorithm> NSROOT::create(const std::string& name, uint64_t block_size, uint64_t key_size)
{
    if (name == "AES")
    {
        return std::make_unique<AES>(key_size);
    }
    else if (name == "SM4")
    {
        return std::make_unique<SM4>();
    }
    else if (name == "Camellia")
    {
        return std::make_unique<Camellia>(key_size);
    }
    else if (name == "Twofish")
    {
        return std::make_unique<Twofish>(key_size);
    }
    return nullptr;
}


#define NS_ROOT(name) dog_torch__crypto__sym__block__##name
#define NS_ALG(name) dog_torch__crypto__sym__block__algorithm__##name
#define CRYPTO_BASE(name) dog_torch__crypto__##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

NS_ALG(ConfigArray)* NS_ALG(get_all)()
{
    return new NS_ALG(ConfigArray){ dog_torch::crypto::sym::block::algorithm::get_all() };
}
void NS_ALG(ConfigArray_delete)(NS_ALG(ConfigArray)** self)
{
    DEFAULT_DESTOTY(self);
}
uint64_t NS_ALG(ConfigArray_size)(const LVALUE(NS_ALG(ConfigArray)) self)
{
    if (self == nullptr) return 0;
    return self->size();
}
const LVALUE(NS_ALG(Config)) NS_ALG(ConfigArray_at)(LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(NS_ALG(ConfigArray)) self, uint64_t index)
{
    using namespace dog_torch::utils;
    if (self == nullptr)
    {
        CppResultSet_reset(result_set, -1, "self is null");
        return nullptr;
    }
    if (index >= self->size())
    {
        CppResultSet_reset(result_set, -1, "index out of range");
        return nullptr;
    }
    return &(self->at(index).get());
}

NS_ROOT(Algorithm)* NS_ROOT(Algorithm_create_c_str)(const char* name, uint64_t block_size, uint64_t key_size)
{
    auto uptr = NSROOT::create(name, block_size, key_size);
    auto ptr = uptr.release();
    return ptr;
}
NS_ROOT(Algorithm)* NS_ROOT(Algorithm_create_string)  (const LVALUE(UTILS(CppString)) name, uint64_t block_size, uint64_t key_size)
{
    using namespace dog_torch::utils;
    auto uptr = NSROOT::create(to_string(name), block_size, key_size);
    auto ptr = uptr.release();
    return ptr;
}

#undef NS_ROOT
#undef NS_ALG
#undef CRYPTO_BASE
#undef SERIALIZE
#undef UTILS

