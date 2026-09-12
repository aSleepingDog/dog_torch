#pragma once
#include "napi_wrapper_utils.h"
#include "crypto_utils_wrapper.h"
#include "crypto/sym/block/sym_block_algorithms.h"
#include "crypto/sym/block/sym_block_paddings.h"
#include "crypto/sym/block/sym_block_modes.h"
namespace BNS = dog_torch::crypto::sym::block;

class BlockAlgorithmConfigWrapper : public Napi::ObjectWrap<BlockAlgorithmConfigWrapper>, public dog_torch::napi::IWrapper
{
public:
    std::unique_ptr<BNS::algorithm::Config> self;
    static inline std::string __NAME = "BlockAlgorithmConfig";
    std::string __name() const override;

    BlockAlgorithmConfigWrapper(const Napi::CallbackInfo& info);

    static Napi::Object create(const Napi::CallbackInfo& info,const BNS::algorithm::Config& config);

    Napi::Value name(const Napi::CallbackInfo& info);
    Napi::Value block_region(const Napi::CallbackInfo& info);
    Napi::Value key_region(const Napi::CallbackInfo& info);

    static inline Napi::FunctionReference constructor;
    static Napi::Object registerClass(Napi::Env env, Napi::Object exports);
};

Napi::Value SymBlockAlgorithmConfigAll(const Napi::CallbackInfo& info);
Napi::Object registerSymBlockAlgorithmConfigAll(Napi::Env env,Napi::Object exports);

class BlockAlgorithmWrapper : public Napi::ObjectWrap<BlockAlgorithmWrapper>, public dog_torch::napi::IWrapper
{
public:
    std::unique_ptr<BNS::algorithm::Algorithm> self;
    static inline std::string __NAME = "BlockAlgorithm";
    std::string __name() const override;
    static inline Napi::FunctionReference constructor;
    BlockAlgorithmWrapper(const Napi::CallbackInfo& info);
    Napi::Value fmt_string(const Napi::CallbackInfo& info);
    static Napi::Value create(const Napi::CallbackInfo& info);

    static Napi::Object registerClass(Napi::Env env, Napi::Object exports);
};

Napi::Value createAES(const Napi::CallbackInfo& info);
Napi::Value createSM4(const Napi::CallbackInfo& info);
Napi::Value createCamellia(const Napi::CallbackInfo& info);
Napi::Value createTwofish(const Napi::CallbackInfo& info);
Napi::Value registerBlockAlgorithm(Napi::Env env, Napi::Object exports);

class BlockPaddingWrapper : public Napi::ObjectWrap<BlockPaddingWrapper>, public dog_torch::napi::IWrapper
{
public:
    std::unique_ptr<BNS::padding::Padding> self;
    static inline std::string __NAME = "BlockPadding";
    std::string __name() const override;
    static inline Napi::FunctionReference constructor;
    BlockPaddingWrapper(const Napi::CallbackInfo& info);
    Napi::Value fmt_string(const Napi::CallbackInfo& info);
    static Napi::Value create(const Napi::CallbackInfo& info);
    
    static Napi::Object registerClass(Napi::Env env, Napi::Object exports);
};

Napi::Value blockPaddingArrays(const Napi::CallbackInfo& info);
Napi::Value createNoPadding(const Napi::CallbackInfo& info);
Napi::Value createPKCS7(const Napi::CallbackInfo& info);
Napi::Value createZERO(const Napi::CallbackInfo& info);
Napi::Value createANSIX923(const Napi::CallbackInfo& info);
Napi::Value createISO10126(const Napi::CallbackInfo& info);
Napi::Value createISO7816_4(const Napi::CallbackInfo& info);
Napi::Value registerBlockPadding(Napi::Env env, Napi::Object exports);

class BlockModeConfigWrapper : public Napi::ObjectWrap<BlockModeConfigWrapper>, public dog_torch::napi::IWrapper
{
public:
    std::unique_ptr<BNS::mode::Config> self;
    static inline std::string __NAME = "BlockModeConfig";
    std::string __name() const override;
    static inline Napi::FunctionReference constructor;
    BlockModeConfigWrapper(const Napi::CallbackInfo& info);
    static Napi::Value create(const Napi::CallbackInfo& info,const BNS::mode::Config& config);
    Napi::Value name(const Napi::CallbackInfo& info);
    Napi::Value params(const Napi::CallbackInfo& info);
    static Napi::Object registerClass(Napi::Env env, Napi::Object exports);
};

Napi::Value SymBlockModeConfigAll(const Napi::CallbackInfo& info);
Napi::Object registerSymBlockModeConfigAll(Napi::Env env,Napi::Object exports);

class BlockModeWrapper : public Napi::ObjectWrap<BlockModeWrapper>, public dog_torch::napi::IWrapper
{
public:
    std::unique_ptr<BNS::mode::Mode> self;
    static inline std::string __NAME = "BlockMode";
    std::string __name() const override;
    static inline Napi::FunctionReference constructor;
    static Napi::Value create(const Napi::CallbackInfo& info);
    BlockModeWrapper(const Napi::CallbackInfo& info);
    Napi::Value fmt_string(const Napi::CallbackInfo& info);
    static Napi::Object registerClass(Napi::Env env, Napi::Object exports);
};

Napi::Value createECB(const Napi::CallbackInfo& info);
Napi::Value createCBC(const Napi::CallbackInfo& info);
Napi::Value createPCBC(const Napi::CallbackInfo& info);
Napi::Value createCFB(const Napi::CallbackInfo& info);
Napi::Value createOFB(const Napi::CallbackInfo& info);
Napi::Value createCTR(const Napi::CallbackInfo& info);
Napi::Value createGCM(const Napi::CallbackInfo& info);
Napi::Value registerBlockMode(Napi::Env env, Napi::Object exports);


class BlockCipherWrapper : public Napi::ObjectWrap<BlockCipherWrapper>, public dog_torch::napi::IWrapper
{
public:
    std::unique_ptr<BNS::BlockCipher> self;
    static inline std::string __NAME = "BlockCipher";
    std::string __name() const override;
    static inline Napi::FunctionReference constructor;
    BlockCipherWrapper(const Napi::CallbackInfo& info);

    static Napi::Value create(const Napi::CallbackInfo& info,BNS::BlockCipher&& c);
    
    Napi::Value fmt_string(const Napi::CallbackInfo& info);

    Napi::Value set_key(const Napi::CallbackInfo& info);
    Napi::Value init(const Napi::CallbackInfo& info);

    Napi::Value serialize(const Napi::CallbackInfo& info);

    Napi::Value encrypt(const Napi::CallbackInfo& info);
    Napi::Value decrypt(const Napi::CallbackInfo& info);

    Napi::Value encrypt_file(const Napi::CallbackInfo& info);
    Napi::Value decrypt_file(const Napi::CallbackInfo& info);

    static Napi::Object registerClass(Napi::Env env, Napi::Object exports);
};
