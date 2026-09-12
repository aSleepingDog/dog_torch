#include "crypto_sym_stream_wrapper.h"

StreamAlgorithmConfigWrapper::StreamAlgorithmConfigWrapper(const Napi::CallbackInfo& info)
: Napi::ObjectWrap<StreamAlgorithmConfigWrapper>(info)
{

}
std::string StreamAlgorithmConfigWrapper::__name() const
{
    return "StreamAlgorithmConfig";
}
Napi::Object StreamAlgorithmConfigWrapper::create(const Napi::CallbackInfo& info,const HNS::algorithm::Config& config)
{
    Napi::Object jsObj = StreamAlgorithmConfigWrapper::constructor.New({});
    StreamAlgorithmConfigWrapper* wrap = StreamAlgorithmConfigWrapper::Unwrap(jsObj);
    wrap->self = std::make_unique<HNS::algorithm::Config>(config);
    return jsObj;
}
Napi::Value StreamAlgorithmConfigWrapper::name(const Napi::CallbackInfo& info)
{
    if(!self) return info.Env().Undefined();
    return Napi::String::New(info.Env(),self->name);
}
Napi::Value StreamAlgorithmConfigWrapper::effective_region(const Napi::CallbackInfo& info)
{
    if(!self) return info.Env().Undefined();
    return Napi::String::New(info.Env(),self->effective_region);
}
Napi::Value StreamAlgorithmConfigWrapper::key_region(const Napi::CallbackInfo& info)
{
    if(!self) return info.Env().Undefined();
    return Napi::String::New(info.Env(),self->key_size_region);
}
Napi::Object StreamAlgorithmConfigWrapper::registerClass(Napi::Env env, Napi::Object exports)
{
    Napi::HandleScope scope(env);
    Napi::Function func = DefineClass(env, "StreamAlgorithmConfig", {
        InstanceAccessor("name", &StreamAlgorithmConfigWrapper::name,nullptr),
        InstanceAccessor("effectiveRegion", &StreamAlgorithmConfigWrapper::effective_region,nullptr),
        InstanceAccessor("keyRegion", &StreamAlgorithmConfigWrapper::key_region,nullptr),
    });
    StreamAlgorithmConfigWrapper::constructor = Napi::Persistent(func);
    StreamAlgorithmConfigWrapper::constructor.SuppressDestruct();
    return exports;
}

Napi::Array SymStreamAllConfig(const Napi::CallbackInfo& info)
{
    auto array = HNS::algorithm::get_all();
    Napi::Array result = Napi::Array::New(info.Env(),array.size());
    for(uint64_t i=0;i<array.size();++i)
    {
        result[i]=StreamAlgorithmConfigWrapper::create(info,array[i].get());
    }
    return result;
}
Napi::Object registerSymStreamAllConfig(Napi::Env env, Napi::Object exports)
{
    exports.Set("all",Napi::Function::New(env, SymStreamAllConfig));
    return exports;
}

StreamAlgorithmWrapper::StreamAlgorithmWrapper(const Napi::CallbackInfo& info)
: Napi::ObjectWrap<StreamAlgorithmWrapper>(info)
{

}
std::string StreamAlgorithmWrapper::__name() const
{
    return "StreamAlgorithm";
}
Napi::Value StreamAlgorithmWrapper::fmt_string(const Napi::CallbackInfo& info)
{
    if(!self) return info.Env().Undefined();
    return Napi::String::New(info.Env(),self->fmt_string());
}
Napi::Value StreamAlgorithmWrapper::create(const Napi::CallbackInfo& info)
{
    Napi::Object obj = StreamAlgorithmWrapper::constructor.New({});
    StreamAlgorithmWrapper* wrap = StreamAlgorithmWrapper::Unwrap(obj);
    std::string name = "";
    uint64_t effi = 0;
    uint64_t key = 0;
    try
    {
        auto args = dog_torch::napi::check_napi_args<
            Napi::String,
            Napi::Number,
            Napi::Number
        >(info);
        name = std::get<0>(args).value;
        effi = std::get<1>(args).value;
        key = std::get<2>(args).value;
    }
    catch(const std::exception& e)
    {
        dog_torch::napi::throw_napi_error(info.Env(),e);
        return info.Env().Undefined();
    }
    wrap->self = HNS::algorithm::create(name,effi,key);
    return obj;
}
Napi::Object StreamAlgorithmWrapper::registerClass(Napi::Env env, Napi::Object exports)
{
    Napi::HandleScope scope(env);
    Napi::Function func = DefineClass(env, "Algorithm", {
        InstanceMethod("fmtString", &StreamAlgorithmWrapper::fmt_string)
    });
    StreamAlgorithmWrapper::constructor = Napi::Persistent(func);
    StreamAlgorithmWrapper::constructor.SuppressDestruct();
    // exports.Set("Algorithm", func);
    return exports;
}
Napi::Value createChaCha(const Napi::CallbackInfo& info)
{
    Napi::Object obj = StreamAlgorithmWrapper::constructor.New({});
    StreamAlgorithmWrapper* wrap = StreamAlgorithmWrapper::Unwrap(obj);
    auto args = dog_torch::napi::check_napi_args<
        Napi::Number
    >(info);
    uint64_t round = std::get<0>(args).value;
    wrap->self = std::make_unique<HNS::algorithm::ChaCha>(round);
    return obj;
}
Napi::Object registerSymStream(Napi::Env env, Napi::Object exports)
{
    exports.Set("create",Napi::Function::New(env,StreamAlgorithmWrapper::create));
    exports.Set("ChaCha",Napi::Function::New(env,createChaCha));
    return exports;
}

StreamCipherWrapper::StreamCipherWrapper(const Napi::CallbackInfo& info)
: Napi::ObjectWrap<StreamCipherWrapper>(info)
{
    if(info.Length()>1)
    {
        Napi::TypeError::New(info.Env(), "no arguments").ThrowAsJavaScriptException();
    }
    if(!dog_torch::napi::isType<StreamAlgorithmWrapper>(info[0]))
    {
        Napi::TypeError::New(info.Env(), "Invalid arguments").ThrowAsJavaScriptException();
    }
    auto alg_p = StreamAlgorithmWrapper::Unwrap(info[0].As<Napi::Object>());
    using dog_torch::crypto::sym::stream::StreamCipher;
    this->self = std::make_unique<StreamCipher>(*(alg_p->self),0,false);
}
std::string StreamCipherWrapper::__name() const
{
    return "StreamCipher";
}
Napi::Value StreamCipherWrapper::create(const Napi::CallbackInfo& info,HNS::StreamCipher&& c)
{
    try
    {
        Napi::Object alg = StreamAlgorithmWrapper::constructor.New({});
        StreamAlgorithmWrapper* alg_wrap = StreamAlgorithmWrapper::Unwrap(alg);
        alg_wrap->self = std::make_unique<HNS::algorithm::ChaCha>(20);

        Napi::Object obj = StreamCipherWrapper::constructor.New({alg});
        StreamCipherWrapper* wrap = StreamCipherWrapper::Unwrap(obj);
        wrap->self = std::make_unique<HNS::StreamCipher>(std::move(c));
        return obj;
    }
    catch(const std::exception& e)
    {
        Napi::Error::New(info.Env(),e.what()).ThrowAsJavaScriptException();
    }
    return info.Env().Undefined();
}
Napi::Value StreamCipherWrapper::fmt_string(const Napi::CallbackInfo& info)
{
    if(!self) return info.Env().Undefined();
    return Napi::String::New(info.Env(),self->fmt_string());
}
Napi::Value StreamCipherWrapper::set_key(const Napi::CallbackInfo& info)
{
    if(self)
    {
        if(info.Length()>1)
        {
            Napi::TypeError::New(info.Env(), "no arguments").ThrowAsJavaScriptException();
        }
        if(!dog_torch::napi::isType<BinaryDataWrapper>(info[0]))
        {
            Napi::TypeError::New(info.Env(), "Invalid arguments").ThrowAsJavaScriptException();
        }
        auto key = BinaryDataWrapper::Unwrap(info[0].As<Napi::Object>())->data();
        self->set_key(key);
    }
    return info.Env().Undefined();
}
Napi::Value StreamCipherWrapper::serialize(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self);
    return BinaryDataWrapper::create(BinaryData{self->serialize().serialize()});
}
Napi::Value StreamCipherWrapper::init(const Napi::CallbackInfo& info)
{
    if(self)
    {
        self->init();
    }
    return info.Env().Undefined();
}
Napi::Value StreamCipherWrapper::encrypt(const Napi::CallbackInfo& info)
{
    try
    {
        NOT_EMPTY(self);
        auto args0 = dog_torch::napi::check_napi_args_optional<
            BinaryDataWrapper,
            Napi::Number
        >(info);
        auto args1 = dog_torch::napi::check_napi_args_optional<
            BinaryDataWrapper
        >(info);
        BinaryData a;
        if(args0)
        {
            a = std::get<0>(args0.value()).value->data();
            uint64_t start = std::get<1>(args0.value()).value;
            a = a.sub_bytes_pos(start,a.size());
        }
        else if(args1)
        {
            a = std::get<0>(args1.value()).value->data();
        }
        else
        {
            throw std::runtime_error("Invalid arguments");
        }
        auto b = self->encrypt(a);
        return BinaryDataWrapper::create(b);
    }
    catch(const std::exception& e)
    {
        Napi::Error::New(info.Env(),e.what()).ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
}
Napi::Value StreamCipherWrapper::decrypt(const Napi::CallbackInfo& info)
{
    try
    {
        NOT_EMPTY(self);
        auto args0 = dog_torch::napi::check_napi_args_optional<
            BinaryDataWrapper,
            Napi::Number
        >(info);
        auto args1 = dog_torch::napi::check_napi_args_optional<
            BinaryDataWrapper
        >(info);
        BinaryData a;
        if(args0)
        {
            a = std::get<0>(args0.value()).value->data();
            uint64_t start = std::get<1>(args0.value()).value;
            a = a.sub_bytes_pos(start,a.size());
        }
        else if(args1)
        {
            a = std::get<0>(args1.value()).value->data();
        }
        else
        {
            throw std::runtime_error("Invalid arguments");
        }
        auto b = self->decrypt(a);
        return BinaryDataWrapper::create(b);
    }
    catch(const std::exception& e)
    {
        Napi::Error::New(info.Env(),e.what()).ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
}

Napi::Value StreamCipherWrapper::encrypt_file(const Napi::CallbackInfo& info)
{
    try
    {
        auto args0 = dog_torch::napi::check_napi_args_optional<
            Napi::String,
            Napi::String
        >(info);
        auto args1 = dog_torch::napi::check_napi_args_optional<
            Napi::String,
            Napi::Number,
            Napi::String
        >(info);
        std::string input;
        uint64_t start = 0;
        std::string output;
        if(args0)
        {
            input = std::get<0>(args0.value()).value;
            output = std::get<1>(args0.value()).value;
        }
        else if(args1)
        {
            input = std::get<0>(args1.value()).value;
            start = std::get<1>(args1.value()).value;
            output = std::get<2>(args1.value()).value;
        }
        if(!std::filesystem::exists(input))
        {
            dog_torch::napi::throw_napi_error(info.Env(),"input plain file not exict");
        }
        uint64_t total = std::filesystem::file_size(input);
        std::ifstream ifs(input,std::ios::binary);
        ifs.ignore(start);
        std::ofstream ofs(output,std::ios::binary);
        self->encrypt_stream(ifs,total,ofs);
    }
    catch(const std::exception& e)
    {
        dog_torch::napi::throw_napi_error(info.Env(),e);
    }
    return info.Env().Undefined();
}
Napi::Value StreamCipherWrapper::decrypt_file(const Napi::CallbackInfo& info)
{
    try
    {
        auto args0 = dog_torch::napi::check_napi_args_optional<
            Napi::String,
            Napi::String
        >(info);
        auto args1 = dog_torch::napi::check_napi_args_optional<
            Napi::String,
            Napi::Number,
            Napi::String
        >(info);
        std::string input;
        uint64_t start = 0;
        std::string output;
        if(args0)
        {
            input = std::get<0>(args0.value()).value;
            output = std::get<1>(args0.value()).value;
        }
        else if(args1)
        {
            input = std::get<0>(args1.value()).value;
            start = std::get<1>(args1.value()).value;
            output = std::get<2>(args1.value()).value;
        }
        if(!std::filesystem::exists(input))
        {
            dog_torch::napi::throw_napi_error(info.Env(),"input plain file not exict");
        }
        uint64_t total = std::filesystem::file_size(input);
        std::ifstream ifs(input,std::ios::binary);
        ifs.ignore(start);
        std::ofstream ofs(output,std::ios::binary);
        self->decrypt_stream(ifs,total,ofs);
    }
    catch(const std::exception& e)
    {
        dog_torch::napi::throw_napi_error(info.Env(),e);
    }
    return info.Env().Undefined();
}

Napi::Object StreamCipherWrapper::registerClass(Napi::Env env, Napi::Object exports)
{
    Napi::HandleScope scope(env);
    Napi::Function func = DefineClass(env, "Cipher", {
        InstanceMethod("fmtString", &StreamCipherWrapper::fmt_string),
        InstanceMethod("setKey", &StreamCipherWrapper::set_key),
        InstanceMethod("init", &StreamCipherWrapper::init),
        InstanceMethod("serialize",&StreamCipherWrapper::serialize),
        InstanceMethod("encrypt",&StreamCipherWrapper::encrypt),
        InstanceMethod("decrypt",&StreamCipherWrapper::decrypt),
        InstanceMethod("encryptFile",&StreamCipherWrapper::encrypt_file),
        InstanceMethod("decryptFile",&StreamCipherWrapper::decrypt_file),
    });
    StreamCipherWrapper::constructor = Napi::Persistent(func);
    StreamCipherWrapper::constructor.SuppressDestruct();
    exports.Set("Cipher", func);
    return exports;
}