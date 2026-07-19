#include "crypto/sym/block/sym_block_modes.h"

namespace NSROOT = dog_torch::crypto::sym::block::mode;

const std::vector<std::reference_wrapper<const NSROOT::Config>> NSROOT::get_all()
{
    return {
        std::cref(ECB::params_config()),
        std::cref(CBC::params_config()),
        std::cref(PCBC::params_config()),
        std::cref(CFB::params_config()),
        std::cref(CFBb::params_config()),
        std::cref(OFB::params_config()),
        std::cref(OFBb::params_config()),
        std::cref(CTR::params_config()),
        std::cref(CTRb::params_config()),
        std::cref(GCM::params_config())
    };
}

std::unique_ptr<NSROOT::Mode> NSROOT::create(const std::string& name, const padding::Padding& padding, const std::unordered_map<std::string, Param>& params)
{
    if (name == "ECB")
    {
        return std::make_unique<ECB>(padding);
    }
    if (params.find("iv") == params.end() || params.at("iv").index() != static_cast<uint64_t>(ParamType::Binary))
    {
        return nullptr;
    }
    if (name == "CBC")
    {
        return std::make_unique<CBC>(std::get<BinaryData>(params.at("iv")), padding);
    }
    else if (name == "PCBC")
    {
        return std::make_unique<CBC>(std::get<BinaryData>(params.at("iv")), padding);
    }
    if (params.find("shift") == params.end() || params.at("shift").index() != static_cast<uint64_t>(ParamType::UInt64))
    {
        return nullptr;
    }
    if (name == "CFB")
    {
        return std::make_unique<CFB>(
            std::get<BinaryData>(params.at("iv")),
            std::get<uint64_t>(params.at("shift")),
            padding);
    }
    else if (name == "CFBb")
    {
        return std::make_unique<CFBb>(
            std::get<BinaryData>(params.at("iv")),
            std::get<uint64_t>(params.at("shift")),
            padding);
    }
    else if (name == "OFB")
    {
        return std::make_unique<OFB>(
            std::get<BinaryData>(params.at("iv")),
            std::get<uint64_t>(params.at("shift")),
            padding);
    }
    else if (name == "OFBb")
    {
        return std::make_unique<OFBb>(
            std::get<BinaryData>(params.at("iv")),
            std::get<uint64_t>(params.at("shift")),
            padding);
    }
    else if (name == "CTR")
    {
        return std::make_unique<CTR>(
            std::get<BinaryData>(params.at("iv")),
            std::get<uint64_t>(params.at("shift")),
            padding);
    }
    else if (name == "CTRb")
    {
        return std::make_unique<CTRb>(
            std::get<BinaryData>(params.at("iv")),
            std::get<uint64_t>(params.at("shift")),
            padding);
    }
    else if (name == "GCM")
    {
        BinaryData aad;
        uint64_t tag_out = 16;
        if (params.find("aad") != params.end() && params.at("aad").index() == static_cast<uint64_t>(ParamType::Binary))
        {
            aad = std::get<BinaryData>(params.at("aad"));
        }
        if (params.find("tag_out") != params.end() && params.at("tag_out").index() == static_cast<uint64_t>(ParamType::UInt64))
        {
            tag_out = std::get<uint64_t>(params.at("tag_out"));
        }
        return std::make_unique<GCM>(
            std::get<BinaryData>(params.at("iv")),
            std::get<uint64_t>(params.at("shift")),
            padding, aad, tag_out
        );
    }
    else
    {
        return nullptr;
    }
}

#define NS_ROOT(name) dog_torch__crypto__sym__block__##name
#define NS_MODE(name) dog_torch__crypto__sym__block__mode__##name
#define CRYPTO_BASE(name) dog_torch__crypto__##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

NS_MODE(ConfigVector)* NS_MODE(get_all)()
{
    return new NS_MODE(ConfigVector){
        NSROOT::get_all()
    };
}
void NS_MODE(ConfigVector_delete)(NS_MODE(ConfigVector)** self)
{
    DEFAULT_DESTOTY(self);
}
uint64_t NS_MODE(ConfigVector_size)(const LVALUE(NS_MODE(ConfigVector)) self)
{
    return self == nullptr ? 0 : self->size();
}
const LVALUE(NS_MODE(Config)) NS_MODE(ConfigVector_at)(LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(NS_MODE(ConfigVector)) self, uint64_t index)
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

NS_ROOT(Mode)* NS_ROOT(Mode_create_c_str)(const char* name, const LVALUE(NS_ROOT(Padding)) padding, const LVALUE(CRYPTO_BASE(ParamHashMap)) params)
{
    auto uptr = NSROOT::create(name, *padding, *params);
    auto ptr = uptr.release();
    return ptr;
}
NS_ROOT(Mode)* NS_ROOT(Mode_create_string)(const LVALUE(UTILS(CppString)) name, const LVALUE(NS_ROOT(Padding)) padding, const LVALUE(CRYPTO_BASE(ParamHashMap)) params)
{
    auto uptr = NSROOT::create(dog_torch::utils::to_string(name), *padding, *params);
    auto ptr = uptr.release();
    return ptr;
}

#undef NS_ROOT
#undef NS_PADDING
#undef CRYPTO_BASE
#undef SERIALIZE
#undef UTILS