#include "crypto_utils_wrapper.h"

std::unordered_map<std::string, Param> to_napi_object(const Napi::Object& obj)
{
    std::unordered_map<std::string, Param> result;
    Napi::Array keys = obj.GetPropertyNames();
    for (uint32_t i = 0; i < keys.Length(); ++i)
    {
        std::string key = keys.Get(i).As<Napi::String>();
        Napi::Value value = obj.Get(key);
        Param param;
        if (value.IsNumber())
        {
            param = static_cast<uint64_t>(value.As<Napi::Number>().Int64Value());
        }
        else if (value.IsBigInt())
        {
            bool tp = false;
            param = static_cast<uint64_t>(value.As<Napi::BigInt>().Int64Value(&tp));
        }
        else if (value.IsString())
        {
            param = value.As<Napi::String>().Utf8Value();
        }
        else if (value.IsBoolean())
        {
            param = value.As<Napi::Boolean>().Value();
        }
        result.emplace(std::move(key), std::move(param));
    }
    return result;
}

Napi::Object registerCryptoTypeEnum(Napi::Env env)
{
    Napi::Object enumObj = Napi::Object::New(env);

    enumObj["Bool"] = Napi::Number::New(env, 0);
    enumObj["UInt64"] = Napi::Number::New(env, 1);
    enumObj["String"] = Napi::Number::New(env, 2);
    enumObj["Binary"] = Napi::Number::New(env, 3);
    enumObj["Hash"] = Napi::Number::New(env, 4);

    enumObj[static_cast<uint32_t>(0)] = Napi::String::New(env, "Bool");
    enumObj[static_cast<uint32_t>(1)] = Napi::String::New(env, "UInt64");
    enumObj[static_cast<uint32_t>(2)] = Napi::String::New(env, "String");
    enumObj[static_cast<uint32_t>(3)] = Napi::String::New(env, "Binary");
    enumObj[static_cast<uint32_t>(4)] = Napi::String::New(env, "Hash");

    enumObj.Freeze();
    return enumObj;
}

ParamInfoWrapper::ParamInfoWrapper(const Napi::CallbackInfo& info)
 : Napi::ObjectWrap<ParamInfoWrapper>(info)
{
    
}
std::string ParamInfoWrapper::__name() const
{
    return "ParamInfo";
}
Napi::Object ParamInfoWrapper::create(const Napi::CallbackInfo& info, const dog_torch::crypto::ParamInfo& param_info)
{
    Napi::Object jsObj = s_constructor.New({});
    ParamInfoWrapper* wrap = ParamInfoWrapper::Unwrap(jsObj);
    wrap->self = std::make_unique<dog_torch::crypto::ParamInfo>(param_info);
    return jsObj;
}
Napi::Value ParamInfoWrapper::type(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self);
    return Napi::Number::New(info.Env(),static_cast<uint32_t>(self->type));
}
Napi::Value ParamInfoWrapper::msg(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self);
    return Napi::String::New(info.Env(),self->msg);
}

Napi::Object ParamInfoWrapper::registerClass(Napi::Env env, Napi::Object exports)
{
    Napi::Function func = DefineClass(env, "ParamInfo", {
        InstanceAccessor("type", &ParamInfoWrapper::type, nullptr),
        InstanceAccessor("msg", &ParamInfoWrapper::msg, nullptr)
    });
    s_constructor = Napi::Persistent(func);
    // exports.Set("ParamInfo", func);
    return exports;
}

Napi::Value from_cpp_map(const Napi::CallbackInfo& info, const std::map<std::string,dog_torch::crypto::ParamInfo>& params)
{
    Napi::Object obj = Napi::Object::New(info.Env());
    for(auto [k,v] : params)
    {
        obj.Set(k,ParamInfoWrapper::create(info,v));
    }
    return obj;
}

std::unordered_map<std::string,dog_torch::crypto::Param> from_js_obj(const Napi::Object& obj)
{
    auto result = std::unordered_map<std::string,dog_torch::crypto::Param>();
    for(auto it = obj.begin();it!=obj.end();++it)
    {
        std::string key = (*it).first.As<Napi::String>().Utf8Value();
        Napi::Value v = (*it).second.AsValue();
        if(v.IsBoolean())
        {
            result[key] = v.As<Napi::Boolean>().Value();
        }
        else if(v.IsNumber())
        {
            result[key] = static_cast<uint64_t>(v.As<Napi::Number>().Int64Value());
        }
        else if(v.IsBigInt())
        {
            bool t = false;
            result[key] = static_cast<uint64_t>(v.As<Napi::BigInt>().Uint64Value(&t));
        }
        else if(v.IsString())
        {
            result[key] = v.As<Napi::String>().Utf8Value();
        }
        else if(dog_torch::napi::isType<BinaryDataWrapper>(v))
        {
            result[key] = BinaryDataWrapper::Unwrap(v.As<Napi::Object>())->data();
        }
    }
    return result;
}
