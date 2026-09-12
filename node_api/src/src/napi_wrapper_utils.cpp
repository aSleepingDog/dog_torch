#include "napi_wrapper_utils.h"
std::string dog_torch::napi::IWrapper::__name() const
{
    return "";
}
void dog_torch::napi::throw_napi_error(const Napi::Env& env, const std::exception& e)
{
    Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
}
void dog_torch::napi::throw_napi_error(const Napi::Env& env, const std::string& e)
{
    Napi::Error::New(env, e).ThrowAsJavaScriptException();
}