#include "TLV_wrapper.h"

Napi::Object registerTLVTypeEnum(Napi::Env env)
{
    Napi::Object obj = Napi::Object::New(env);

    using namespace dog_torch::serialize::tlv;

    obj["Null"] = Napi::Number::New(env, static_cast<int>(Type::Null));
    obj["Bool"] = Napi::Number::New(env, static_cast<int>(Type::Bool));
    obj["Int"] = Napi::Number::New(env, static_cast<int>(Type::Integer));
    obj["Float"] = Napi::Number::New(env, static_cast<int>(Type::Float));
    obj["String"] = Napi::Number::New(env, static_cast<int>(Type::String));

    obj[static_cast<int>(Type::Null)] = Napi::String::New(env, "Null");
    obj[static_cast<int>(Type::Bool)] = Napi::String::New(env, "Bool");
    obj[static_cast<int>(Type::Integer)] = Napi::String::New(env, "Int");
    obj[static_cast<int>(Type::Float)] = Napi::String::New(env, "Float");
    obj[static_cast<int>(Type::String)] = Napi::String::New(env, "String");

    obj.Freeze();
    return obj;
}

std::string TlvObjectWrapper::__name() const
{
    return TlvObjectWrapper::__NAME;
}

TlvObjectWrapper::TlvObjectWrapper(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<TlvObjectWrapper>(info)
{
    if(info.Length() == 0)
    {
        this->self = std::make_unique<TlvObject>();
        return;
    }
    if(info.Length() == 2 && info[0].IsNumber())
    {
        uint64_t type = info[0].As<Napi::Number>().Int64Value();
        if(type==0)
        {
            this->self = std::make_unique<TlvObject>();
        }
        else if(type==1 && info[1].IsBoolean())
        {
            this->self = std::make_unique<TlvObject>(info[1].As<Napi::Boolean>().Value());
        }
        else if(type==2 && info[1].IsNumber())
        {
            auto n = info[1].As<Napi::Number>().Int64Value();
            using dog_torch::math::number::Integer64;
            Integer64 i(n);
            this->self = std::make_unique<TlvObject>(i);
        }
        else if(type==3 && info[1].IsNumber())
        {
            auto n = info[1].As<Napi::Number>().DoubleValue();
            this->self = std::make_unique<TlvObject>(n);
        }
        else if(type==5 && info[1].IsString())
        {
            auto s = info[1].As<Napi::String>().Utf8Value();
            using dog_torch::serialize::tlv::MIBString;
            MIBString str(s);
            this->self = std::make_unique<TlvObject>(str);
        }
        // else if(type==4 && info[1].IsArrayBuffer())
        else
        {
            throw Napi::Error::New(info.Env(), "Invalid arguments");
        }
    }
}

Napi::Value TlvObjectWrapper::value(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self);
    if(this->self->type() == dog_torch::serialize::tlv::Type::Null)
    {
        return Napi::Value();
    }
    else if(this->self->type() == dog_torch::serialize::tlv::Type::Bool)
    {
        return Napi::Boolean::New(info.Env(), this->self->to_bool());
    }
    else if(this->self->type() == dog_torch::serialize::tlv::Type::Integer)
    {
        auto i = this->self->to_integer();
        return Napi::Number::New(info.Env(), static_cast<int64_t>(1)*i.sign*i.number );
    }
    else if(this->self->type() == dog_torch::serialize::tlv::Type::Float)
    {
        return Napi::Number::New(info.Env(), this->self->to_float());
    }
    else if(this->self->type() == dog_torch::serialize::tlv::Type::String)
    {
        auto s = this->self->to_string();
        return Napi::String::New(info.Env(), s.string);
    }
    return info.Env().Undefined();
}

Napi::Value TlvObjectWrapper::serialize(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self);
    auto data = this->self->serialize();
    Napi::ArrayBuffer buffer = Napi::ArrayBuffer::New(info.Env(), data.size());
    std::memcpy(buffer.Data(), data.data(), data.size());
    return buffer;
}

Napi::Object TlvObjectWrapper::registerClass(Napi::Env env, Napi::Object exports)
{
    Napi::HandleScope scope(env);
    Napi::Function func = DefineClass(env, "TlvObject", {
        InstanceMethod("value", &TlvObjectWrapper::value),
        InstanceMethod("serialize", &TlvObjectWrapper::serialize)
    });
    TlvObjectWrapper::constructor = Napi::Persistent(func);
    TlvObjectWrapper::constructor.SuppressDestruct();
    exports.Set(TlvObjectWrapper::__NAME, func);
    return exports;
}