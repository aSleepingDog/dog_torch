#include "crypto_hash_wrapper.h"

HashConfigWrapper::HashConfigWrapper(const Napi::CallbackInfo& info)
:Napi::ObjectWrap<HashConfigWrapper>(info)
{

}
std::string HashConfigWrapper::__name() const
{
    return "HashConfig";
}    
Napi::Object HashConfigWrapper::create(const Napi::CallbackInfo& info, const NSROOT::algorithm::Config& param_info)
{
    Napi::Object jsObj = constructor.New({});
    HashConfigWrapper* wrap = HashConfigWrapper::Unwrap(jsObj);
    wrap->self = std::make_unique<NSROOT::algorithm::Config>(param_info);
    return jsObj;
}
Napi::Value HashConfigWrapper::name(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self);
    return Napi::String::New(info.Env(),self->name);
};
Napi::Value HashConfigWrapper::region(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self);
    return Napi::String::New(info.Env(),self->region);
};
Napi::Value HashConfigWrapper::params(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self);
    return from_cpp_map(info,this->self->params);
};

Napi::Object HashConfigWrapper::registerClass(Napi::Env env, Napi::Object exports)
{
    Napi::HandleScope scope(env);
    Napi::Function func = DefineClass(env, "HashConfig", {
        InstanceAccessor("name", &HashConfigWrapper::name, nullptr),
        InstanceAccessor("region", &HashConfigWrapper::region, nullptr),
        InstanceAccessor("params", &HashConfigWrapper::params, nullptr)
    });
    HashConfigWrapper::constructor = Napi::Persistent(func);
    HashConfigWrapper::constructor.SuppressDestruct();
    // exports.Set("Config", func);
    return exports;
};

Napi::Array hashAllConfig(const Napi::CallbackInfo& info)
{
    auto array = NSROOT::algorithm::get_all();
    Napi::Array result = Napi::Array::New(info.Env(),array.size());
    for(uint32_t i=0;i<array.size();++i)
    {
        result.Set(i,HashConfigWrapper::create(info,array[i]));
    }
    result.Freeze();
    return result;
}
Napi::Object registerHashConfigs(Napi::Env env, Napi::Object exports)
{
    exports.Set("all",Napi::Function::New(env, hashAllConfig));
    return exports;
}

HashAlgorithmWrapper::HashAlgorithmWrapper(const Napi::CallbackInfo& info)
:Napi::ObjectWrap<HashAlgorithmWrapper>(info)
{}
std::string HashAlgorithmWrapper::__name() const
{
    return "HashAlgorithm";
}    
Napi::Function HashAlgorithmWrapper::functionClass(Napi::Env env)
{
    return DefineClass(env, "Algorithm", {
        StaticMethod("create",&HashAlgorithmWrapper::create),
        InstanceMethod("fmtString", &HashAlgorithmWrapper::fmt_string)
    });
}
Napi::Value HashAlgorithmWrapper::create(const Napi::CallbackInfo& info)
{
    try
    {
        std::string name;
        uint64_t effi = 0;
        std::unordered_map<std::string,Param> params;
        auto args0 = dog_torch::napi::check_napi_args_optional<
            Napi::String,
            Napi::Number
        >(info);
        auto args1 = dog_torch::napi::check_napi_args_optional<
            Napi::String,
            Napi::Number,
            Napi::Object
        >(info);
        if(args0)
        {
            name = std::get<0>(args0.value()).value;
            effi = std::get<1>(args0.value()).value;
        }
        else if(args1)
        {
            name = std::get<0>(args1.value()).value;
            effi = std::get<1>(args1.value()).value;
            params = from_js_obj(std::get<2>(args1.value()).value.As<Napi::Object>());
        }
        else
        {
            throw std::runtime_error("invalid arguments");
        }

        Napi::Object jsObj = constructor.New({});
        HashAlgorithmWrapper* wrap = HashAlgorithmWrapper::Unwrap(jsObj);
        wrap->self = NSROOT::algorithm::create(name,effi,params);
        return jsObj;
    }
    catch(const std::exception& e)
    {
        dog_torch::napi::throw_napi_error(info.Env(),e);
        return info.Env().Undefined();
    }
}
NSROOT::algorithm::Algorithm& HashAlgorithmWrapper::data()
{
    return *(this->self);
}
Napi::Value HashAlgorithmWrapper::fmt_string(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self);
    return Napi::String::New(info.Env(),self->fmt_string());
}

Napi::Object HashAlgorithmWrapper::registerClass(Napi::Env env, Napi::Object exports)
{
    Napi::HandleScope scope(env);
    Napi::Function func = DefineClass(env, "Algorithm", {
        InstanceMethod("fmtString", &HashAlgorithmWrapper::fmt_string)
    });
    HashAlgorithmWrapper::constructor = Napi::Persistent(func);
    HashAlgorithmWrapper::constructor.SuppressDestruct();
    // exports.Set("Algorithm", func);
    return exports;
}

Napi::Value createSHA2(const Napi::CallbackInfo& info)
{
    uint64_t effi = 0;
    try
    {
        auto args = dog_torch::napi::check_napi_args<
            Napi::Number>(info);
        effi = std::get<0>(args).value;
        Napi::Object jsObj = HashAlgorithmWrapper::constructor.New({});
        HashAlgorithmWrapper* wrap = HashAlgorithmWrapper::Unwrap(jsObj);
        using dog_torch::crypto::hash::algorithm::SHA2;
        wrap->self = std::make_unique<SHA2>(effi);
        return jsObj;
    }
    catch(const std::exception& e)
    {
        dog_torch::napi::throw_napi_error(info.Env(),e);
        return info.Env().Undefined();
    }
}
Napi::Value createSM3(const Napi::CallbackInfo& info)
{
    Napi::Object jsObj = HashAlgorithmWrapper::constructor.New({});
    HashAlgorithmWrapper* wrap = HashAlgorithmWrapper::Unwrap(jsObj);
    using dog_torch::crypto::hash::algorithm::SM3;
    wrap->self = std::make_unique<SM3>();
    return jsObj;
}
Napi::Value createBLAKE2(const Napi::CallbackInfo& info)
{
    uint64_t effi = 0;
    std::unordered_map<std::string,Param> params;
    try
    {
        auto args = dog_torch::napi::check_napi_args<
            Napi::Number,
            Napi::Object
        >(info);
        effi = std::get<0>(args).value;
        params = from_js_obj(std::get<1>(args).value.As<Napi::Object>());

        Napi::Object jsObj = HashAlgorithmWrapper::constructor.New({});
        HashAlgorithmWrapper* wrap = HashAlgorithmWrapper::Unwrap(jsObj);
        using dog_torch::crypto::hash::algorithm::BLAKE2;
        using dog_torch::crypto::ParamType;
        uint8_t out_size = 0;
        BinaryData key, salt, person;
        if (params.find("out_size") != params.end() && params.at("out_size").index() == (size_t)ParamType::UInt64)
        {
            out_size = static_cast<uint8_t>(std::get<uint64_t>(params.at("out_size")));
        }
        if (params.find("key") != params.end() && params.at("key").index() == (size_t)ParamType::Binary)
        {
            key = std::get<BinaryData>(params.at("key"));
        }
        if (params.find("salt") != params.end() && params.at("salt").index() == (size_t)ParamType::Binary)
        {
            salt = std::get<BinaryData>(params.at("salt"));
        }
        if (params.find("person") != params.end() && params.at("personalization").index() == (size_t)ParamType::Binary)
        {
            person = std::get<BinaryData>(params.at("personalization"));
        }
        wrap->self = std::make_unique<BLAKE2>(effi, out_size, key, salt, person);
        return jsObj;
    }
    catch(const std::exception& e)
    {
        dog_torch::napi::throw_napi_error(info.Env(),e);
        return info.Env().Undefined();
    }

}

Napi::Object registerHash(Napi::Env env, Napi::Object exports)
{
    exports.Set("create",Napi::Function::New(env, HashAlgorithmWrapper::create));
    exports.Set("SHA2",Napi::Function::New(env, createSHA2));
    exports.Set("SM3",Napi::Function::New(env, createSM3));
    exports.Set("BLAKE2",Napi::Function::New(env, createBLAKE2));
    return exports;
}

HashGeneratorWrapper::HashGeneratorWrapper(const Napi::CallbackInfo& info)
: Napi::ObjectWrap<HashGeneratorWrapper>(info)
{
    if(info.Length()<1)
    {
        Napi::TypeError::New(info.Env(), "no arguments").ThrowAsJavaScriptException();
    }
    if(!dog_torch::napi::isType<HashAlgorithmWrapper>(info[0]))
    {
        Napi::TypeError::New(info.Env(), "Invalid arguments").ThrowAsJavaScriptException();
    }
    auto alg_p = HashAlgorithmWrapper::Unwrap(info[0].As<Napi::Object>());
    using dog_torch::crypto::hash::Generator;
    this->self = std::make_unique<Generator>(*(alg_p->self));
}
std::string HashGeneratorWrapper::__name() const
{
    return "HashGenerator";
}    
Napi::Value HashGeneratorWrapper::fmt_string(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self);
    return Napi::String::New(info.Env(),this->self->fmt_string());
}
Napi::Value HashGeneratorWrapper::caculate_binary(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self);
    auto args = dog_torch::napi::check_napi_args<
        BinaryDataWrapper
    >(info);
    // auto bin_p = BinaryDataWrapper::Unwrap(info[0].As<Napi::Object>());
    auto bin = std::get<0>(args).value->data();
    self->init();
    auto result = self->calculate(bin);
    return BinaryDataWrapper::create(result);
}
Napi::Value HashGeneratorWrapper::caculate_file(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self);
    auto args = dog_torch::napi::check_napi_args<
        Napi::String
    >(info);
    auto path = std::get<0>(args).value;
    self->init();
    if(!std::filesystem::exists(path))
    {
        Napi::TypeError::New(info.Env(), "file not exist").ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
    uint64_t total = std::filesystem::file_size(path);
    std::ifstream ifs(path,std::ios::binary);
    auto result = self->calculate(ifs,total);
    return BinaryDataWrapper::create(result);
}
Napi::Object HashGeneratorWrapper::registerClass(Napi::Env env, Napi::Object exports)
{
    Napi::HandleScope scope(env);
    Napi::Function func = DefineClass(env, "Generator", {
        InstanceMethod("fmtString", &HashGeneratorWrapper::fmt_string),
        InstanceMethod("calcuateBinary", &HashGeneratorWrapper::caculate_binary),
        InstanceMethod("calcuateFile", &HashGeneratorWrapper::caculate_file)
    });
    HashGeneratorWrapper::constructor = Napi::Persistent(func);
    HashGeneratorWrapper::constructor.SuppressDestruct();
    exports.Set("Generator", func);
    return exports;
}