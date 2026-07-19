#include "crypto/sym/block/sym_block_paddings.h"

namespace NSROOT = dog_torch::crypto::sym::block::padding;

const std::vector<std::reference_wrapper<const NSROOT::Config>> NSROOT::get_all()
{
    return {
        std::cref(NoPadding::allowed_config()),
        std::cref(PKCS7::allowed_config()),
        std::cref(ZERO::allowed_config()),
        std::cref(ANSIX923::allowed_config()),
        std::cref(ISO10126::allowed_config()),
        std::cref(ISO7816_4::allowed_config())
    };
}

std::unique_ptr<NSROOT::Padding> NSROOT::create(const std::string& name)
{
    if (name == PKCS7::allowed_config().name)
    {
        return std::make_unique<PKCS7>();
    }
    else if (name == ZERO::allowed_config().name)
    {
        return std::make_unique<ZERO>();
    }
    else if (name == ANSIX923::allowed_config().name)
    {
        return std::make_unique<ANSIX923>();
    }
    else if (name == ISO10126::allowed_config().name)
    {
        return std::make_unique<ISO10126>();
    }
    else if (name == ISO7816_4::allowed_config().name)
    {
        return std::make_unique<ISO7816_4>();
    }
    else if (name == NoPadding::allowed_config().name)
    {
        return std::make_unique<NoPadding>();
    }
    else
    {
        return nullptr;
    }
}

#define NS_ROOT(name) dog_torch__crypto__sym__block__##name
#define NS_PADDING(name) dog_torch__crypto__sym__block__padding__##name
#define CRYPTO_BASE(name) dog_torch__crypto__##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

NS_PADDING(ConfigVector)* NS_PADDING(get_all)()
{
    return new NS_PADDING(ConfigVector)(NSROOT::get_all());
}
void NS_PADDING(ConfigVector_delete)(NS_PADDING(ConfigVector)** self)
{
    DEFAULT_DESTOTY(self);
}
uint64_t NS_PADDING(ConfigVector_size)(const LVALUE(NS_PADDING(ConfigVector)) self)
{
    if (self == nullptr) return 0;
    return self->size();
}
const LVALUE(NS_PADDING(Config)) NS_PADDING(ConfigVector_at)(LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(NS_PADDING(ConfigVector)) self, uint64_t index)
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

NS_ROOT(Padding)* NS_ROOT(Padding_create_c_str)(const char* name)
{
    return NSROOT::create(name).release();
}
NS_ROOT(Padding)* NS_ROOT(Padding_create_string)(const LVALUE(UTILS(CppString)) name)
{
    using namespace dog_torch::utils;
    return NSROOT::create(to_string(name)).release();
}

#undef NS_ROOT
#undef NS_PADDING
#undef CRYPTO_BASE
#undef SERIALIZE
#undef UTILS