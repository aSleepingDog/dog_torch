#pragma once
#include "napi_wrapper_utils.h"
#include "crypto_utils_wrapper.h"
#include "crypto/sym/stream/sym_stream_algorithms.h"
namespace HNS = dog_torch::crypto::sym::stream;

class StreamAlgorithmConfigWrapper : public Napi::ObjectWrap<StreamAlgorithmConfigWrapper>, public dog_torch::napi::IWrapper
{
public:
    std::unique_ptr<HNS::algorithm::Config> self;
    static inline std::string __NAME = "StreamAlgorithmConfig";
    std::string __name() const override;

    StreamAlgorithmConfigWrapper(const Napi::CallbackInfo& info);
    static Napi::Object create(const Napi::CallbackInfo& info,const HNS::algorithm::Config& config);
    Napi::Value name(const Napi::CallbackInfo& info);
    Napi::Value effective_region(const Napi::CallbackInfo& info);
    Napi::Value key_region(const Napi::CallbackInfo& info);

    static inline Napi::FunctionReference constructor;
    static Napi::Object registerClass(Napi::Env env, Napi::Object exports);
};

Napi::Array SymStreamAllConfig(const Napi::CallbackInfo& info);
Napi::Object registerSymStreamAllConfig(Napi::Env env, Napi::Object exports);

class StreamAlgorithmWrapper : public Napi::ObjectWrap<StreamAlgorithmWrapper>, public dog_torch::napi::IWrapper
{
public:
    static inline std::string __NAME = "StreamAlgorithm";
    std::string __name() const override;
    std::unique_ptr<HNS::algorithm::Algorithm> self;
    StreamAlgorithmWrapper(const Napi::CallbackInfo& info);
    static Napi::Value create(const Napi::CallbackInfo& info);
    Napi::Value fmt_string(const Napi::CallbackInfo& info);

    static inline Napi::FunctionReference constructor;
    static Napi::Object registerClass(Napi::Env env, Napi::Object exports);
};

Napi::Value createChaCha(const Napi::CallbackInfo& info);
Napi::Object registerSymStream(Napi::Env env, Napi::Object exports);

class StreamCipherWrapper : public Napi::ObjectWrap<StreamCipherWrapper>, public dog_torch::napi::IWrapper
{
public:
    static inline std::string __NAME = "StreamCipher";
    std::string __name() const override;
    std::unique_ptr<HNS::StreamCipher> self;
    static inline Napi::FunctionReference constructor;
    StreamCipherWrapper(const Napi::CallbackInfo& info);

    static Napi::Value create(const Napi::CallbackInfo& info,HNS::StreamCipher&& c);
    
    Napi::Value fmt_string(const Napi::CallbackInfo& info);
    Napi::Value serialize(const Napi::CallbackInfo& info);

    Napi::Value set_key(const Napi::CallbackInfo& info);
    Napi::Value init(const Napi::CallbackInfo& info);

    Napi::Value encrypt(const Napi::CallbackInfo& info);
    Napi::Value decrypt(const Napi::CallbackInfo& info);

    Napi::Value encrypt_file(const Napi::CallbackInfo& info);
    Napi::Value decrypt_file(const Napi::CallbackInfo& info);

    static Napi::Object registerClass(Napi::Env env, Napi::Object exports);
};
