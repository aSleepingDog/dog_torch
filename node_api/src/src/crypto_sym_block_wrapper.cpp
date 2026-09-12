#include "crypto_sym_block_wrapper.h"

BlockAlgorithmConfigWrapper::BlockAlgorithmConfigWrapper(const Napi::CallbackInfo& info)
: Napi::ObjectWrap<BlockAlgorithmConfigWrapper>(info)
{}
std::string BlockAlgorithmConfigWrapper::__name() const
{
    return "BlockAlgorithmConfig";
}
Napi::Object BlockAlgorithmConfigWrapper::create(const Napi::CallbackInfo& info,const BNS::algorithm::Config& config)
{
    Napi::Object obj = constructor.New({});
    auto wrap = BlockAlgorithmConfigWrapper::Unwrap(obj);
    wrap->self = std::make_unique<BNS::algorithm::Config>(config);
    return obj;
}

Napi::Value BlockAlgorithmConfigWrapper::name(const Napi::CallbackInfo& info)
{
    if(!self) return info.Env().Undefined();
    return Napi::String::New(info.Env(),self->name);
}
Napi::Value BlockAlgorithmConfigWrapper::block_region(const Napi::CallbackInfo& info)
{
    if(!self) return info.Env().Undefined();
    return Napi::String::New(info.Env(),self->block_size_region);
}
Napi::Value BlockAlgorithmConfigWrapper::key_region(const Napi::CallbackInfo& info)
{
    if(!self) return info.Env().Undefined();
    return Napi::String::New(info.Env(),self->key_size_region);
}

Napi::Object BlockAlgorithmConfigWrapper::registerClass(Napi::Env env, Napi::Object exports)
{
    Napi::HandleScope scope(env);
    Napi::Function func = DefineClass(env,"BlockAlgorithmConfig",
        {
            InstanceAccessor("name",&BlockAlgorithmConfigWrapper::name,nullptr),
            InstanceAccessor("blockRegion",&BlockAlgorithmConfigWrapper::block_region,nullptr),
            InstanceAccessor("keyRegion",&BlockAlgorithmConfigWrapper::key_region,nullptr),
        }
    );
    BlockAlgorithmConfigWrapper::constructor = Napi::Persistent(func);
    BlockAlgorithmConfigWrapper::constructor.SuppressDestruct();
    return exports;
}

Napi::Value SymBlockAlgorithmConfigAll(const Napi::CallbackInfo& info)
{
    auto arrays = BNS::algorithm::get_all();
    Napi::Array result = Napi::Array::New(info.Env(),arrays.size());
    for(uint64_t i=0;i<arrays.size();++i)
    {
        result.Set(i,BlockAlgorithmConfigWrapper::create(info,arrays[i]));
    }
    return result;
}
Napi::Object registerSymBlockAlgorithmConfigAll(Napi::Env env,Napi::Object exports)
{
    exports.Set("all",Napi::Function::New(env, &SymBlockAlgorithmConfigAll));
    return exports;
}

BlockAlgorithmWrapper::BlockAlgorithmWrapper(const Napi::CallbackInfo& info)
:Napi::ObjectWrap<BlockAlgorithmWrapper>(info){}
std::string BlockAlgorithmWrapper::__name() const
{
    return "BlockAlgorithm";
}
Napi::Value BlockAlgorithmWrapper::fmt_string(const Napi::CallbackInfo& info)
{
    if(!self) return info.Env().Undefined();
    return Napi::String::New(info.Env(),self->fmt_string());
}
Napi::Value BlockAlgorithmWrapper::create(const Napi::CallbackInfo& info)
{
    try
    {
        auto args = dog_torch::napi::check_napi_args<
            Napi::String,
            Napi::Number,
            Napi::Number
        >(info);
        std::string name = std::get<0>(args).value;
        uint64_t block = std::get<1>(args).value;
        uint64_t key = std::get<2>(args).value;
        Napi::Object obj = constructor.New({});
        BlockAlgorithmWrapper* wrap = BlockAlgorithmWrapper::Unwrap(obj);
        wrap->self = BNS::algorithm::create(name,block,key);
        return obj;
    }
    catch(const std::exception& e)
    {
        Napi::Error::New(info.Env(),e.what()).ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
}

Napi::Object BlockAlgorithmWrapper::registerClass(Napi::Env env, Napi::Object exports)
{
    Napi::HandleScope scope(env);
    Napi::Function func = DefineClass(env,"BlockAlgorithm",
        {
            InstanceMethod("fmtString",&BlockAlgorithmWrapper::fmt_string)
        }
    );
    BlockAlgorithmWrapper::constructor = Napi::Persistent(func);
    BlockAlgorithmWrapper::constructor.SuppressDestruct();
    return exports;
}

Napi::Value createAES(const Napi::CallbackInfo& info)
{
    try
    {
        auto args = dog_torch::napi::check_napi_args<
            Napi::Number
        >(info);
        uint64_t key = std::get<0>(args).value;
        Napi::Object obj = BlockAlgorithmWrapper::constructor.New({});
        auto wrap = BlockAlgorithmWrapper::Unwrap(obj);
        wrap->self = std::make_unique<BNS::algorithm::AES>(key);
        return obj;
    }
    catch(const std::exception& e)
    {
        Napi::TypeError::New(info.Env(), e.what()).ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
}
Napi::Value createSM4(const Napi::CallbackInfo& info)
{
    Napi::Object obj = BlockAlgorithmWrapper::constructor.New({});
    auto wrap = BlockAlgorithmWrapper::Unwrap(obj);
    wrap->self = std::make_unique<BNS::algorithm::SM4>();
    return obj;
}
Napi::Value createCamellia(const Napi::CallbackInfo& info)
{
    try
    {
        auto args = dog_torch::napi::check_napi_args<
            Napi::Number
        >(info);
        uint64_t key = std::get<0>(args).value;
        Napi::Object obj = BlockAlgorithmWrapper::constructor.New({});
        auto wrap = BlockAlgorithmWrapper::Unwrap(obj);
        wrap->self = std::make_unique<BNS::algorithm::Camellia>(key);
        return obj;
    }
    catch(const std::exception& e)
    {
        Napi::TypeError::New(info.Env(), e.what()).ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
}
Napi::Value createTwofish(const Napi::CallbackInfo& info)
{
    try
    {
        auto args = dog_torch::napi::check_napi_args<
            Napi::Number
        >(info);
        uint64_t key = std::get<0>(args).value;
        Napi::Object obj = BlockAlgorithmWrapper::constructor.New({});
        auto wrap = BlockAlgorithmWrapper::Unwrap(obj);
        wrap->self = std::make_unique<BNS::algorithm::Twofish>(key);
        return obj;
    }
    catch(const std::exception& e)
    {
        Napi::TypeError::New(info.Env(), e.what()).ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
}
Napi::Value registerBlockAlgorithm(Napi::Env env, Napi::Object exports)
{
    exports.Set("create",Napi::Function::New(env, &BlockAlgorithmWrapper::create));
    exports.Set("AES",Napi::Function::New(env, &createAES));
    exports.Set("SM4",Napi::Function::New(env, &createSM4));
    exports.Set("Camellia",Napi::Function::New(env, &createCamellia));
    exports.Set("Twofish",Napi::Function::New(env, &createTwofish));
    return exports;
}

BlockPaddingWrapper::BlockPaddingWrapper(const Napi::CallbackInfo& info)
: Napi::ObjectWrap<BlockPaddingWrapper>(info){}
std::string BlockPaddingWrapper::__name() const
{
    return "BlockPadding";
}
Napi::Value BlockPaddingWrapper::create(const Napi::CallbackInfo& info)
{
    try
    {
        auto args = dog_torch::napi::check_napi_args<
            Napi::String
        >(info);
        std::string name = std::get<0>(args).value;
        Napi::Object obj = BlockPaddingWrapper::constructor.New({});
        auto wrap = BlockPaddingWrapper::Unwrap(obj);
        wrap->self = BNS::padding::create(name);
        return obj;
    }
    catch(const std::exception& e)
    {
        Napi::TypeError::New(info.Env(), e.what()).ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
}
Napi::Value BlockPaddingWrapper::fmt_string(const Napi::CallbackInfo& info)
{
    if(!self) return info.Env().Undefined();
    return Napi::String::New(info.Env(),self->fmt_string());
}
Napi::Object BlockPaddingWrapper::registerClass(Napi::Env env, Napi::Object exports)
{
    Napi::HandleScope scope(env);
    Napi::Function func = DefineClass(env,"BlockPadding",
        {
            InstanceMethod("fmtString",&BlockPaddingWrapper::fmt_string)
        }
    );
    BlockPaddingWrapper::constructor = Napi::Persistent(func);
    BlockPaddingWrapper::constructor.SuppressDestruct();
    return exports;
}

Napi::Value blockPaddingArrays(const Napi::CallbackInfo& info)
{
    auto array = BNS::padding::get_all();
    Napi::Array js_array = Napi::Array::New(info.Env(), array.size());
    for(size_t i = 0; i < array.size(); ++i)
    {
        js_array[i] = Napi::String::New(info.Env(), array[i].get().name);
    }
    return js_array;
}
Napi::Value createNoPadding(const Napi::CallbackInfo& info)
{
    Napi::Object obj = BlockPaddingWrapper::constructor.New({});
    auto wrap = BlockPaddingWrapper::Unwrap(obj);
    wrap->self = std::make_unique<BNS::padding::NoPadding>();
    return obj;
}
Napi::Value createPKCS7(const Napi::CallbackInfo& info)
{
    Napi::Object obj = BlockPaddingWrapper::constructor.New({});
    auto wrap = BlockPaddingWrapper::Unwrap(obj);
    wrap->self = std::make_unique<BNS::padding::PKCS7>();
    return obj;
}
Napi::Value createZERO(const Napi::CallbackInfo& info)
{
    Napi::Object obj = BlockPaddingWrapper::constructor.New({});
    auto wrap = BlockPaddingWrapper::Unwrap(obj);
    wrap->self = std::make_unique<BNS::padding::ZERO>();
    return obj;
}
Napi::Value createANSIX923(const Napi::CallbackInfo& info)
{
    Napi::Object obj = BlockPaddingWrapper::constructor.New({});
    auto wrap = BlockPaddingWrapper::Unwrap(obj);
    wrap->self = std::make_unique<BNS::padding::ANSIX923>();
    return obj;
}
Napi::Value createISO10126(const Napi::CallbackInfo& info)
{
    Napi::Object obj = BlockPaddingWrapper::constructor.New({});
    auto wrap = BlockPaddingWrapper::Unwrap(obj);
    wrap->self = std::make_unique<BNS::padding::ISO10126>();
    return obj;
}
Napi::Value createISO7816_4(const Napi::CallbackInfo& info)
{
    Napi::Object obj = BlockPaddingWrapper::constructor.New({});
    auto wrap = BlockPaddingWrapper::Unwrap(obj);
    wrap->self = std::make_unique<BNS::padding::ISO7816_4>();
    return obj;
}
Napi::Value registerBlockPadding(Napi::Env env, Napi::Object exports)
{
    exports.Set("all",Napi::Function::New(env, &blockPaddingArrays));
    exports.Set("create",Napi::Function::New(env, &BlockPaddingWrapper::create));
    exports.Set("NoPadding",Napi::Function::New(env, &createNoPadding));
    exports.Set("PKCS7",Napi::Function::New(env, &createPKCS7));
    exports.Set("ZERO",Napi::Function::New(env, &createZERO));
    exports.Set("ANSIX923",Napi::Function::New(env, &createANSIX923));
    exports.Set("ISO10126",Napi::Function::New(env, &createISO10126));
    exports.Set("ISO7816_4",Napi::Function::New(env, &createISO7816_4));
    return exports;
}

BlockModeConfigWrapper::BlockModeConfigWrapper(const Napi::CallbackInfo& info)
: Napi::ObjectWrap<BlockModeConfigWrapper>(info){}
std::string BlockModeConfigWrapper::__name() const
{
    return "BlockModeConfig";
}
Napi::Value BlockModeConfigWrapper::create(const Napi::CallbackInfo& info,const BNS::mode::Config& config)
{
    Napi::Object obj = BlockModeConfigWrapper::constructor.New({});
    auto wrap = BlockModeConfigWrapper::Unwrap(obj);
    wrap->self = std::make_unique<BNS::mode::Config>(config);
    return obj;
}
Napi::Value BlockModeConfigWrapper::name(const Napi::CallbackInfo& info)
{
    if(!self) return info.Env().Undefined();
    return Napi::String::New(info.Env(),self->name);
}
Napi::Value BlockModeConfigWrapper::params(const Napi::CallbackInfo& info)
{
    if(!self) return info.Env().Undefined();
    return from_cpp_map(info,self->params);
}
Napi::Object BlockModeConfigWrapper::registerClass(Napi::Env env, Napi::Object exports)
{
    Napi::HandleScope scope(env);
    Napi::Function func = DefineClass(env,"BlockModeConfig",
        {
            InstanceAccessor("name",&BlockModeConfigWrapper::name,nullptr),
            InstanceAccessor("params",&BlockModeConfigWrapper::params,nullptr)
        }
    );
    BlockModeConfigWrapper::constructor = Napi::Persistent(func);
    BlockModeConfigWrapper::constructor.SuppressDestruct();
    return exports;
}

Napi::Value SymBlockModeConfigAll(const Napi::CallbackInfo& info)
{
    auto arrays = BNS::mode::get_all();
    Napi::Array ret = Napi::Array::New(info.Env(),arrays.size());
    for(size_t i = 0;i < arrays.size();i++)
    {
        ret.Set(i,BlockModeConfigWrapper::create(info,arrays[i].get()));
    }
    return ret;
}
Napi::Object registerSymBlockModeConfigAll(Napi::Env env,Napi::Object exports)
{
    exports.Set("all",Napi::Function::New(env, &SymBlockModeConfigAll));
    return exports;
}

BlockModeWrapper::BlockModeWrapper(const Napi::CallbackInfo& info)
: Napi::ObjectWrap<BlockModeWrapper>(info){}
std::string BlockModeWrapper::__name() const
{
    return "BlockMode";
}
Napi::Value BlockModeWrapper::fmt_string(const Napi::CallbackInfo& info)
{
    if(!self) return info.Env().Undefined();
    return Napi::String::New(info.Env(),self->fmt_string());
}
Napi::Object BlockModeWrapper::registerClass(Napi::Env env, Napi::Object exports)
{
    Napi::HandleScope scope(env);
    Napi::Function func = DefineClass(env,"BlockMode",
        {
            InstanceMethod("fmtString",&BlockModeWrapper::fmt_string)
        }
    );
    BlockModeWrapper::constructor = Napi::Persistent(func);
    BlockModeWrapper::constructor.SuppressDestruct();
    return exports;
}
Napi::Value BlockModeWrapper::create(const Napi::CallbackInfo& info)
{
    try
    {
        auto args = dog_torch::napi::check_napi_args<
            Napi::String,
            BlockPaddingWrapper,
            Napi::Object
        >(info);
        std::string name = std::get<0>(args).value;
        auto padding = std::get<1>(args).value->self.get();
        auto params = from_js_obj(std::get<2>(args).value.As<Napi::Object>());
        Napi::Object obj = BlockModeWrapper::constructor.New({});
        auto wrap = BlockModeWrapper::Unwrap(obj);
        wrap->self = BNS::mode::create(name,*padding,params);
        return obj;
    }
    catch(const std::exception& e)
    {
        Napi::TypeError::New(info.Env(),e.what()).ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
}
Napi::Value createECB(const Napi::CallbackInfo& info)
{
    if(info.Length() < 1)
    {
        Napi::TypeError::New(info.Env(),"Invalid arguments").ThrowAsJavaScriptException();
    }
    if(!dog_torch::napi::isType<BlockPaddingWrapper>(info[0]))
    {
        Napi::TypeError::New(info.Env(),"Invalid arguments").ThrowAsJavaScriptException();
    }
    auto padding = BlockPaddingWrapper::Unwrap(info[0].As<Napi::Object>())->self.get();
    Napi::Object obj = BlockModeWrapper::constructor.New({});
    auto wrap = BlockModeWrapper::Unwrap(obj);
    wrap->self = std::make_unique<BNS::mode::ECB>(*padding);
    return obj;
}
Napi::Value createCBC(const Napi::CallbackInfo& info)
{
    try
    {
        auto args = dog_torch::napi::check_napi_args<
            BinaryDataWrapper,
            BlockPaddingWrapper
        >(info);
        auto iv = std::get<0>(args).value->data();
        auto padding = std::get<1>(args).value->self.get();
        Napi::Object obj = BlockModeWrapper::constructor.New({});
        auto wrap = BlockModeWrapper::Unwrap(obj);
        wrap->self = std::make_unique<BNS::mode::CBC>(iv,*padding);
        return obj;
    }
    catch(const std::exception& e)
    {
        Napi::TypeError::New(info.Env(),e.what()).ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
}
Napi::Value createPCBC(const Napi::CallbackInfo& info)
{
    try
    {
        auto args = dog_torch::napi::check_napi_args<
            BinaryDataWrapper,
            BlockPaddingWrapper
        >(info);

        auto iv = std::get<0>(args).value->data();
        auto padding = std::get<1>(args).value->self.get();
        Napi::Object obj = BlockModeWrapper::constructor.New({});
        auto wrap = BlockModeWrapper::Unwrap(obj);
        wrap->self = std::make_unique<BNS::mode::PCBC>(iv,*padding);
        return obj;
    }
    catch(const std::exception& e)
    {
        Napi::TypeError::New(info.Env(),e.what()).ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
}
Napi::Value createCFB(const Napi::CallbackInfo& info)
{
    try
    {
        auto args = dog_torch::napi::check_napi_args<
            BinaryDataWrapper,
            Napi::Boolean,
            Napi::Number,
            BlockPaddingWrapper
        >(info);
        auto iv = std::get<0>(args).value->data();
        auto is_byte = std::get<1>(args).value;
        uint64_t shift = std::get<2>(args).value;
        auto padding = std::get<3>(args).value->self.get();
        Napi::Object obj = BlockModeWrapper::constructor.New({});
        auto wrap = BlockModeWrapper::Unwrap(obj);
        if(is_byte)
        {
            wrap->self = std::make_unique<BNS::mode::CFB>(iv,shift,*padding);
        }
        else
        {
            wrap->self = std::make_unique<BNS::mode::CFBb>(iv,shift,*padding);
        }
        return obj;
    }
    catch(const std::exception& e)
    {
        Napi::TypeError::New(info.Env(),e.what()).ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
}
Napi::Value createOFB(const Napi::CallbackInfo& info)
{
    try
    {
        auto args = dog_torch::napi::check_napi_args<
            BinaryDataWrapper,
            Napi::Boolean,
            Napi::Number,
            BlockPaddingWrapper
        >(info);
        auto iv = std::get<0>(args).value->data();
        auto is_byte = std::get<1>(args).value;
        uint64_t shift = std::get<2>(args).value;
        auto padding = std::get<3>(args).value->self.get();
        Napi::Object obj = BlockModeWrapper::constructor.New({});
        auto wrap = BlockModeWrapper::Unwrap(obj);
        if(is_byte)
        {
            wrap->self = std::make_unique<BNS::mode::OFB>(iv,shift,*padding);
        }
        else
        {
            wrap->self = std::make_unique<BNS::mode::OFBb>(iv,shift,*padding);
        }
        return obj;
    }
    catch(const std::exception& e)
    {
        Napi::TypeError::New(info.Env(),e.what()).ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
}
Napi::Value createCTR(const Napi::CallbackInfo& info)
{
    try
    {
        auto args = dog_torch::napi::check_napi_args<
            BinaryDataWrapper,
            Napi::Boolean,
            Napi::Number,
            BlockPaddingWrapper
        >(info);
        auto iv = std::get<0>(args).value->data();
        auto is_byte = std::get<1>(args).value;
        uint64_t shift = std::get<2>(args).value;
        auto padding = std::get<3>(args).value->self.get();
        Napi::Object obj = BlockModeWrapper::constructor.New({});
        auto wrap = BlockModeWrapper::Unwrap(obj);
        if(is_byte)
        {
            wrap->self = std::make_unique<BNS::mode::CTR>(iv,shift,*padding);
        }
        else
        {
            wrap->self = std::make_unique<BNS::mode::CTRb>(iv,shift,*padding);
        }
        return obj;
    }
    catch(const std::exception& e)
    {
        Napi::TypeError::New(info.Env(),e.what()).ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
}
Napi::Value createGCM(const Napi::CallbackInfo& info)
{
    try
    {
        auto args = dog_torch::napi::check_napi_args<
            BinaryDataWrapper,
            Napi::Number,
            BlockPaddingWrapper,
            BinaryDataWrapper,
            Napi::Number
        >(info);
        auto iv = std::get<0>(args).value->data();
        uint64_t shift = std::get<1>(args).value;
        auto padding = std::get<2>(args).value->self.get();
        auto a = std::get<3>(args).value->data();
        uint64_t tag_len = std::get<4>(args).value;

        Napi::Object obj = BlockModeWrapper::constructor.New({});
        auto wrap = BlockModeWrapper::Unwrap(obj);
        wrap->self = std::make_unique<BNS::mode::GCM>(iv,shift,*padding,a,tag_len);
        return obj;
    }
    catch(const std::exception& e)
    {
        Napi::TypeError::New(info.Env(),e.what()).ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
}
Napi::Value registerBlockMode(Napi::Env env, Napi::Object exports)
{
    exports.Set("create",Napi::Function::New(env,BlockModeWrapper::create));
    exports.Set("ECB",Napi::Function::New(env,createECB));
    exports.Set("CBC",Napi::Function::New(env,createCBC));
    exports.Set("PCBC",Napi::Function::New(env,createPCBC));
    exports.Set("CFB",Napi::Function::New(env,createCFB));
    exports.Set("OFB",Napi::Function::New(env,createOFB));
    exports.Set("CTR",Napi::Function::New(env,createCTR));
    exports.Set("GCM",Napi::Function::New(env,createGCM));
    return exports;
}

BlockCipherWrapper::BlockCipherWrapper(const Napi::CallbackInfo& info)
: Napi::ObjectWrap<BlockCipherWrapper>(info)
{
    try
    {
        auto args = dog_torch::napi::check_napi_args<
            BlockAlgorithmWrapper,
            BlockModeWrapper
        >(info);
        auto alg = std::get<0>(args).value->self.get();
        auto mode = std::get<1>(args).value->self.get();
        self = std::make_unique<BNS::BlockCipher>(*alg,*mode);
    }
    catch(const std::exception& e)
    {
        Napi::Error::New(info.Env(),e.what()).ThrowAsJavaScriptException();
    }
}
std::string BlockCipherWrapper::__name() const
{
    return "BlockCipher";
}
Napi::Value BlockCipherWrapper::create(const Napi::CallbackInfo& info,BNS::BlockCipher&& c)
{
    try
    {
        Napi::Value alg = createSM4(info);
            auto padding = BlockPaddingWrapper::Unwrap(createPKCS7(info).As<Napi::Object>())->self.get();
        Napi::Value mode = BlockModeWrapper::constructor.New({});
            auto mode_wrap = BlockModeWrapper::Unwrap(mode.As<Napi::Object>());
            mode_wrap->self = std::make_unique<BNS::mode::ECB>(*padding);

        Napi::Object obj = BlockCipherWrapper::constructor.New({alg,mode});
        auto wrap = BlockCipherWrapper::Unwrap(obj);
        wrap->self = std::make_unique<BNS::BlockCipher>(std::move(c));
        return obj;
    }
    catch(const std::exception& e)
    {
        Napi::Error::New(info.Env(),e.what()).ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
}
Napi::Value BlockCipherWrapper::fmt_string(const Napi::CallbackInfo& info)
{
    if(!self) return info.Env().Undefined();
    return Napi::String::New(info.Env(),self->fmt_string());
}

Napi::Value BlockCipherWrapper::set_key(const Napi::CallbackInfo& info)
{
    if(!self) return info.Env().Undefined();
    try
    {
        if(info.Length() < 1)
        {
            Napi::TypeError::New(info.Env(),"Invalid arguments").ThrowAsJavaScriptException();
        }
        if(!dog_torch::napi::isType<BinaryDataWrapper>(info[0].As<Napi::Object>()))
        {
            Napi::TypeError::New(info.Env(),"Invalid arguments").ThrowAsJavaScriptException();
        }
        self->set_key(BinaryDataWrapper::Unwrap(info[0].As<Napi::Object>())->data());
        return info.Env().Undefined();
    }
    catch(const std::exception& e)
    {
        Napi::Error::New(info.Env(),e.what()).ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
}
Napi::Value BlockCipherWrapper::init(const Napi::CallbackInfo& info)
{
    try
    {
        if(!self) return info.Env().Undefined();
        self->init();
    }
    catch(const std::exception& e)
    {
        Napi::Error::New(info.Env(),e.what()).ThrowAsJavaScriptException();
    }
    return info.Env().Undefined();
}
Napi::Value BlockCipherWrapper::serialize(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self);
    return BinaryDataWrapper::create(BinaryData{self->serialize().serialize()});
}
Napi::Value BlockCipherWrapper::encrypt(const Napi::CallbackInfo& info)
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
        std::cout << a.size() << std::endl;
        auto b = self->encrypt(a);
        return BinaryDataWrapper::create(b);
    }
    catch(const std::exception& e)
    {
        Napi::Error::New(info.Env(),e.what()).ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
}
Napi::Value BlockCipherWrapper::decrypt(const Napi::CallbackInfo& info)
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

Napi::Value BlockCipherWrapper::encrypt_file(const Napi::CallbackInfo& info)
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
Napi::Value BlockCipherWrapper::decrypt_file(const Napi::CallbackInfo& info)
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

Napi::Object BlockCipherWrapper::registerClass(Napi::Env env, Napi::Object exports)
{
    Napi::Function func = DefineClass(env,"Cipher",{
        InstanceMethod("fmtString",&BlockCipherWrapper::fmt_string),
        InstanceMethod("setKey",&BlockCipherWrapper::set_key),
        InstanceMethod("init",&BlockCipherWrapper::init),
        InstanceMethod("serialize",&BlockCipherWrapper::serialize),
        InstanceMethod("encrypt",&BlockCipherWrapper::encrypt),
        InstanceMethod("decrypt",&BlockCipherWrapper::decrypt),
        InstanceMethod("encryptFile",&BlockCipherWrapper::encrypt_file),
        InstanceMethod("decryptFile",&BlockCipherWrapper::decrypt_file),
    });
    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();
    exports.Set("Cipher",func);
    return exports;
}