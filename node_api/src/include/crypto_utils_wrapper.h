#pragma once
#include "napi_wrapper_utils.h"
#include "BinaryData_wrapper.h"
#include "crypto/crypto_base.h"

using Param = dog_torch::crypto::Param;

std::unordered_map<std::string, Param> to_napi_object(const Napi::Object& obj);

Napi::Object registerCryptoTypeEnum(Napi::Env env);

class ParamInfoWrapper : public Napi::ObjectWrap<ParamInfoWrapper>, public dog_torch::napi::IWrapper
{
private:
    std::unique_ptr<dog_torch::crypto::ParamInfo> self = nullptr;
    static inline Napi::FunctionReference s_constructor;
public:
    ParamInfoWrapper(const Napi::CallbackInfo& info);    
    static inline std::string __NAME = "ParamInfo";
    std::string __name() const override;
    static Napi::Object create(const Napi::CallbackInfo& info, const dog_torch::crypto::ParamInfo& param_info);

    Napi::Value type(const Napi::CallbackInfo& info);

    Napi::Value msg(const Napi::CallbackInfo& info);

    static Napi::Object registerClass(Napi::Env env, Napi::Object exports);
};

Napi::Value from_cpp_map(const Napi::CallbackInfo& info, const std::map<std::string,dog_torch::crypto::ParamInfo>& params);
std::unordered_map<std::string,dog_torch::crypto::Param> from_js_obj(const Napi::Object& obj);