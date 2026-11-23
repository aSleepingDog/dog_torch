#pragma once
#include "napi_wrapper_utils.h"
#include "serialize/tlv.h"
using TlvObject = dog_torch::serialize::tlv::Value;
namespace dnapi = dog_torch::napi;

Napi::Object registerTLVTypeEnum(Napi::Env env);

class TlvObjectWrapper : public Napi::ObjectWrap<TlvObjectWrapper>, public dog_torch::napi::IWrapper
{
private:
    std::unique_ptr<TlvObject> self = nullptr;
    static inline Napi::FunctionReference constructor;
public:
    std::string __name() const override;
    static inline std::string __NAME = "TlvObject";

    TlvObjectWrapper(const Napi::CallbackInfo& info);

    Napi::Value value(const Napi::CallbackInfo& info);

    Napi::Value serialize(const Napi::CallbackInfo& info);

    static Napi::Object registerClass(Napi::Env env, Napi::Object exports);

};