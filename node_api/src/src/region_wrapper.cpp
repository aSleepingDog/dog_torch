#include "region_wrapper.h"
std::string NumberIteratorWrapper::__name() const
{
    return "NumberIterator";
}

NumberIteratorWrapper::NumberIteratorWrapper::NumberIteratorWrapper(const Napi::CallbackInfo& info) : Napi::ObjectWrap<NumberIteratorWrapper>(info)
{
    try
    {
        auto args = dnapi::check_napi_args<Napi::String>(info);
        this->self_ = std::make_unique<NumberIterator>(
            std::get<0>(args).value
        );
    }
    catch (const std::exception& e)
    {
        dnapi::throw_napi_error(info.Env(), e);
    }
}

Napi::Value NumberIteratorWrapper::haveNext(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self_);
    return Napi::Boolean::New(info.Env(), this->self_->have_next());
}

Napi::Value NumberIteratorWrapper::next(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self_);
    try
    {
        return Napi::Number::New(info.Env(), this->self_->next());
    }
    catch (const std::exception& e)
    {
        dnapi::throw_napi_error(info.Env(), e);
        return info.Env().Undefined();
    }
}

Napi::Object NumberIteratorWrapper::registerClass(Napi::Env env, Napi::Object exports)
{
    Napi::HandleScope scope(env);
    Napi::Function func = DefineClass(env, "NumberIterator", {
        InstanceMethod("haveNext", &NumberIteratorWrapper::haveNext),
        InstanceMethod("next", &NumberIteratorWrapper::next),
        });

    exports.Set("NumberIterator", func);
    return exports;
}