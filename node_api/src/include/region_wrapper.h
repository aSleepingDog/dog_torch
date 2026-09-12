#pragma once
#include "napi_wrapper_utils.h"
#include "math/region.h"
namespace dnapi = dog_torch::napi;
using dog_torch::math::region::NumberIterator;
class NumberIteratorWrapper : public Napi::ObjectWrap<NumberIteratorWrapper>, public dog_torch::napi::IWrapper
{
    std::unique_ptr<NumberIterator> self_ = nullptr;
public:
    static inline std::string __NAME = "NumberIterator";
    std::string __name() const override;

    NumberIteratorWrapper(const Napi::CallbackInfo& info);

    Napi::Value haveNext(const Napi::CallbackInfo& info);

    Napi::Value next(const Napi::CallbackInfo& info);

    static Napi::Object registerClass(Napi::Env env, Napi::Object exports);
};