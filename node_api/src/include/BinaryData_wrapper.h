#pragma once
#include "napi_wrapper_utils.h"
#include "serialize/BinaryData.h"
using dog_torch::serialize::BinaryData;
namespace dnapi = dog_torch::napi;

Napi::Object registerBinaryTypeEnum(Napi::Env env);

class BinaryDataWrapper : public Napi::ObjectWrap<BinaryDataWrapper>, public dog_torch::napi::IWrapper
{
private:
    std::unique_ptr<BinaryData> self_ = nullptr;
    static inline Napi::FunctionReference constructor;
public:
    std::string __name() const override;
    static inline std::string __NAME = "BinaryData";

    BinaryDataWrapper(const Napi::CallbackInfo& info);

    Napi::Value toString(const Napi::CallbackInfo& info);

    Napi::Value toBinaryString(const Napi::CallbackInfo& info);

    Napi::Value toHexString(const Napi::CallbackInfo& info);

    Napi::Value toBase64String(const Napi::CallbackInfo& info);

    Napi::Value size(const Napi::CallbackInfo& info);

    static Napi::Value create(const BinaryData& data);

    static Napi::Value concat(const Napi::CallbackInfo& info);

    Napi::Value subBytes(const Napi::CallbackInfo& info);

    static Napi::Object registerClass(Napi::Env env, Napi::Object exports);

    BinaryData data();
};

struct BinaryParams
{
    std::vector<char> params;
    BinaryParams(const std::vector<char>& params) : params(params) {};
    std::string fmt_string();
    std::string fmt_binary(const BinaryData& data);
};

struct BinaryParamsWrapper : public Napi::ObjectWrap<BinaryParamsWrapper>, public dog_torch::napi::IWrapper
{
    std::vector<char> params;
    static inline Napi::FunctionReference constructor;

    std::string __name() const override;
    static inline std::string __NAME = "BinaryParams";
    BinaryParamsWrapper(const Napi::CallbackInfo& info);

    Napi::Value fmt_binary(const Napi::CallbackInfo& info);
    std::string fmt_binary(const BinaryData& data);

    std::string fmt_string();

    BinaryParams toBinaryParams();

    Napi::Value fmt_string(const Napi::CallbackInfo& info);

    static Napi::Object registerClass(Napi::Env env, Napi::Object exports);

};
