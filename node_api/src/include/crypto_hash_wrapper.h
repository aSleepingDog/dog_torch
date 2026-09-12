#pragma once
#include "napi_wrapper_utils.h"
#include "crypto_utils_wrapper.h"
#include "crypto/hash/hash_algorithms.h"

namespace NSROOT = dog_torch::crypto::hash;

class HashConfigWrapper : public Napi::ObjectWrap<HashConfigWrapper>, public dog_torch::napi::IWrapper
{
private:
    std::unique_ptr<NSROOT::algorithm::Config> self = nullptr;
public:
    static inline std::string __NAME = "HashConfig";
    std::string __name() const override;

    HashConfigWrapper(const Napi::CallbackInfo& info);
    static Napi::Object create(const Napi::CallbackInfo& info, const NSROOT::algorithm::Config& param_info);
    Napi::Value name(const Napi::CallbackInfo& info);

    Napi::Value region(const Napi::CallbackInfo& info);

    Napi::Value params(const Napi::CallbackInfo& info);

    static inline Napi::FunctionReference constructor;
    static Napi::Object registerClass(Napi::Env env, Napi::Object exports);
};

Napi::Array hashAllConfig(const Napi::CallbackInfo& info);
Napi::Object registerHashConfigs(Napi::Env env, Napi::Object exports);

class HashAlgorithmWrapper : public Napi::ObjectWrap<HashAlgorithmWrapper>, public dog_torch::napi::IWrapper
{
public:
    std::unique_ptr<NSROOT::algorithm::Algorithm> self = nullptr;
    static inline std::string __NAME = "HashAlgorithm";
    std::string __name() const override;

    HashAlgorithmWrapper(const Napi::CallbackInfo& info);
    static Napi::Value create(const Napi::CallbackInfo& info);
    NSROOT::algorithm::Algorithm& data();

    Napi::Value fmt_string(const Napi::CallbackInfo& info);

    static Napi::Function functionClass(Napi::Env env);
    static inline Napi::FunctionReference constructor;
    static Napi::Object registerClass(Napi::Env env, Napi::Object exports);
};

Napi::Value createSHA2(const Napi::CallbackInfo& info);
Napi::Value createSM3(const Napi::CallbackInfo& info);
Napi::Value createBLAKE2(const Napi::CallbackInfo& info);
Napi::Object registerHash(Napi::Env env, Napi::Object exports);

class HashGeneratorWrapper : public Napi::ObjectWrap<HashGeneratorWrapper>, public dog_torch::napi::IWrapper
{
public:
    static inline std::string __NAME = "HashGenerator";
    std::string __name() const override;
    std::unique_ptr<dog_torch::crypto::hash::Generator> self;
    
    HashGeneratorWrapper(const Napi::CallbackInfo& info);

    Napi::Value fmt_string(const Napi::CallbackInfo& info);

    Napi::Value caculate_binary(const Napi::CallbackInfo& info);

    Napi::Value caculate_file(const Napi::CallbackInfo& info);

    static inline Napi::FunctionReference constructor;
    static Napi::Object registerClass(Napi::Env env, Napi::Object exports);
};