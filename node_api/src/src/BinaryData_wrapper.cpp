#include "BinaryData_wrapper.h"

Napi::Object registerBinaryTypeEnum(Napi::Env env)
{
    Napi::Object obj = Napi::Object::New(env);

    obj["Utf8"] = Napi::Number::New(env, static_cast<int>(BinaryData::Type::UTF8));
    obj["Binary"] = Napi::Number::New(env, static_cast<int>(BinaryData::Type::Binary));
    obj["Hex"] = Napi::Number::New(env, static_cast<int>(BinaryData::Type::Hex));
    obj["Base64"] = Napi::Number::New(env, static_cast<int>(BinaryData::Type::Base64));

    obj[static_cast<int>(BinaryData::Type::UTF8)] = Napi::String::New(env, "Utf8");
    obj[static_cast<int>(BinaryData::Type::Binary)] = Napi::String::New(env, "Binary");
    obj[static_cast<int>(BinaryData::Type::Hex)] = Napi::String::New(env, "Hex");
    obj[static_cast<int>(BinaryData::Type::Base64)] = Napi::String::New(env, "Base64");

    obj.Freeze();
    return obj;
}

std::string BinaryDataWrapper::__name() const
{
    return "BinaryData";
}

BinaryDataWrapper::BinaryDataWrapper::BinaryDataWrapper(const Napi::CallbackInfo& info) : Napi::ObjectWrap<BinaryDataWrapper>(info)
{
    try
    {
        if (info.Length() == 0)
        {
            self_ = std::make_unique<BinaryData>();
            return;
        }
        auto args = dnapi::check_napi_args<Napi::String, Napi::Number>(info);
        self_ = std::make_unique<BinaryData>(
            std::get<0>(args).value,
            static_cast<dog_torch::serialize::BinaryData::Type>(std::get<1>(args).value)
        );
    }
    catch (const std::exception& e)
    {
        dnapi::throw_napi_error(info.Env(), e);
    }
}

Napi::Value BinaryDataWrapper::create(const BinaryData& data)
{
    Napi::Object obj = BinaryDataWrapper::constructor.New({});
    BinaryDataWrapper* wrap = BinaryDataWrapper::Unwrap(obj);
    wrap->self_ = std::make_unique<BinaryData>(data);
    return obj;
}
Napi::Value BinaryDataWrapper::toString(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self_);
    return Napi::String::New(info.Env(), self_->to_string());
}
Napi::Value BinaryDataWrapper::toBinaryString(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self_);
    return Napi::String::New(info.Env(), self_->to_bin_string());
}
Napi::Value BinaryDataWrapper::toHexString(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self_);
    try
    {
        auto args = dnapi::check_napi_args<Napi::Boolean>(info);
        return Napi::String::New(info.Env(), self_->to_hex_string(std::get<0>(args).value));
    }
    catch (const std::exception& e)
    {
        dnapi::throw_napi_error(info.Env(), e);
        return info.Env().Undefined();
    }
}
Napi::Value BinaryDataWrapper::size(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self_);
    return Napi::Number::New(info.Env(), self_->size());
}
Napi::Value BinaryDataWrapper::concat(const Napi::CallbackInfo& info)
{
    try
    {
        auto args = dnapi::check_napi_args<
            BinaryDataWrapper,BinaryDataWrapper
        >(info);
        auto b0 = std::get<0>(args).value->data();
        auto b1 = std::get<1>(args).value->data();
        return BinaryDataWrapper::create(b0+b1);
    }
    catch (const std::exception& e)
    {
        dnapi::throw_napi_error(info.Env(), e);
    }
    return info.Env().Undefined();
}
Napi::Value BinaryDataWrapper::subBytes(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self_);
    try
    {
        auto args = dnapi::check_napi_args<
            Napi::Number,Napi::Number
        >(info);
        uint64_t b0 = std::get<0>(args).value;
        uint64_t b1 = std::get<1>(args).value;
        return BinaryDataWrapper::create(self_->sub_bytes_pos(b0,b1));
    }
    catch(const std::exception& e)
    {
        dnapi::throw_napi_error(info.Env(), e);
    }
    return info.Env().Undefined();
}
Napi::Value BinaryDataWrapper::toBase64String(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(self_);
    try
    {
        auto args = dnapi::check_napi_args<
            Napi::String,
            Napi::String,
            Napi::String
        >(info);
        return Napi::String::New(info.Env(), self_->to_base64_string(
            std::get<0>(args).value.size() > 0 ? std::get<0>(args).value[0] : '+',
            std::get<1>(args).value.size() > 0 ? std::get<1>(args).value[0] : '/',
            std::get<2>(args).value.size() > 0 ? std::get<2>(args).value[0] : '='
        ));
    }
    catch (const std::exception& e)
    {
        dnapi::throw_napi_error(info.Env(), e);
        return info.Env().Undefined();
    }
}
Napi::Object BinaryDataWrapper::registerClass(Napi::Env env, Napi::Object exports)
{
    Napi::HandleScope scope(env);
    Napi::Function func = DefineClass(env, "BinaryData", {
        InstanceMethod("size", &BinaryDataWrapper::size),
        InstanceMethod("subBytes", &BinaryDataWrapper::subBytes),
        StaticMethod("concat", &BinaryDataWrapper::concat),
        InstanceMethod("toString", &BinaryDataWrapper::toString),
        InstanceMethod("toBinaryString", &BinaryDataWrapper::toBinaryString),
        InstanceMethod("toHexString", &BinaryDataWrapper::toHexString),
        InstanceMethod("toBase64String", &BinaryDataWrapper::toBase64String),
    });
    BinaryDataWrapper::constructor = Napi::Persistent(func);
    BinaryDataWrapper::constructor.SuppressDestruct();
    exports.Set("BinaryData", func);
    return exports;
}

BinaryData BinaryDataWrapper::data()
{
    return *(this->self_);
}

std::string BinaryParams::fmt_string()
{
    std::string result;
    if(this->params.at(0)==static_cast<uint64_t>(BinaryData::Type::UTF8))
    {
        result = "UTF8";
    }
    else if(this->params.at(0)==static_cast<uint64_t>(BinaryData::Type::Binary))
    {
        result = "Binary";
    }
    else if(this->params.at(0)==static_cast<uint64_t>(BinaryData::Type::Hex))
    {
        result = std::format("Hex:{}", this->params.at(1)?"upper":"lower");
    }
    else if(this->params.at(0)==static_cast<uint64_t>(BinaryData::Type::Base64))
    {
        if(params.at(0) == '+' && params.at(1) == '/' && params.at(2) == '=')
        {
            result = "Base64";
        }
        else
        {
            result = std::format("Base64:{}{}{}", this->params.at(1), this->params.at(2), this->params.at(3));
        }
    }
    return result;
}
std::string BinaryParams::fmt_binary(const BinaryData& data)
{
    if(this->params.at(0)==static_cast<uint64_t>(BinaryData::Type::UTF8))
    {
        return data.to_string();
    }
    else if(this->params.at(0)==static_cast<uint64_t>(BinaryData::Type::Binary))
    {
        return data.to_bin_string();
    }
    else if(this->params.at(0)==static_cast<uint64_t>(BinaryData::Type::Hex))
    {
        bool is_upper = this->params.at(1);
        return data.to_hex_string(is_upper);
    }
    else if(this->params.at(0)==static_cast<uint64_t>(BinaryData::Type::Base64))
    {
        char b64_plus = this->params.at(1);
        char b64_slash = this->params.at(2);
        char b64_pad = this->params.at(3);
        return data.to_base64_string(b64_plus,b64_slash,b64_pad);
    }
    else
    {
        throw std::invalid_argument("Invalid BinaryData type in BinaryParamsWrapper");
    }
}

BinaryParamsWrapper::BinaryParamsWrapper(const Napi::CallbackInfo& info)
: Napi::ObjectWrap<BinaryParamsWrapper>(info)
{
    try
    {
        auto args0 = dnapi::check_napi_args_optional<Napi::Number>(info);
        auto args1 = dnapi::check_napi_args_optional<
            Napi::Number,Napi::Boolean
        >(info);
        auto args2 = dnapi::check_napi_args_optional<
            Napi::Number,Napi::String,Napi::String,Napi::String
        >(info);
        if (!args0 && !args1 && !args2)
        {
            throw std::invalid_argument("Invalid arguments for BinaryParamsWrapper constructor");
        }
        else if (args0)
        {
            auto type = std::get<0>(args0.value()).value;
            this->params.push_back(static_cast<char>(type));
            if(type == static_cast<char>(BinaryData::Type::Base64))
            {
                this->params.push_back('+');
                this->params.push_back('/');
                this->params.push_back('=');
            }
            else if(type == static_cast<char>(BinaryData::Type::Hex))
            {
                this->params.push_back(true);
            }
        }
        else if (args1)
        {
            auto type = std::get<0>(args1.value()).value;
            auto is_upper = std::get<1>(args1.value()).value;
            this->params.push_back(static_cast<char>(type));
            if(type == static_cast<char>(BinaryData::Type::Hex))
            {
                this->params.push_back(is_upper);
            }
            else if(type == static_cast<char>(BinaryData::Type::Base64))
            {
                this->params.push_back('+');
                this->params.push_back('/');
                this->params.push_back('=');
            }
        }
        else if (args2)
        {
            auto type = std::get<0>(args2.value()).value;
            auto b64_plus = std::get<1>(args2.value()).value[0];
            auto b64_slash = std::get<2>(args2.value()).value[0];
            auto b64_pad = std::get<3>(args2.value()).value[0];
            this->params.push_back(static_cast<char>(type));
            if(type == static_cast<char>(BinaryData::Type::Base64))
            {
                this->params.push_back(b64_plus);
                this->params.push_back(b64_slash);
                this->params.push_back(b64_pad);
            }
            else if(type == static_cast<char>(BinaryData::Type::Hex))
            {
                this->params.push_back(true);
            }
        }
    }
    catch (const std::exception& e)
    {
        dnapi::throw_napi_error(info.Env(), e);
    }
}
std::string BinaryParamsWrapper::__name() const
{
    return "BinaryParams";
}

std::string BinaryParamsWrapper::fmt_binary(const BinaryData& data)
{
    if(this->params.at(0)==static_cast<uint64_t>(BinaryData::Type::UTF8))
    {
        return data.to_string();
    }
    else if(this->params.at(0)==static_cast<uint64_t>(BinaryData::Type::Binary))
    {
        return data.to_bin_string();
    }
    else if(this->params.at(0)==static_cast<uint64_t>(BinaryData::Type::Hex))
    {
        bool is_upper = this->params.at(1);
        return data.to_hex_string(is_upper);
    }
    else if(this->params.at(0)==static_cast<uint64_t>(BinaryData::Type::Base64))
    {
        char b64_plus = this->params.at(1);
        char b64_slash = this->params.at(2);
        char b64_pad = this->params.at(3);
        return data.to_base64_string(b64_plus,b64_slash,b64_pad);
    }
    else
    {
        throw std::invalid_argument("Invalid BinaryData type in BinaryParamsWrapper");
    }
}
Napi::Value BinaryParamsWrapper::fmt_binary(const Napi::CallbackInfo& info)
{
    try
    {
        auto args = dnapi::check_napi_args<BinaryDataWrapper>(info);
        auto data = std::get<0>(args).value->data();
        return Napi::String::New(info.Env(), this->fmt_binary(data));
    }
    catch (const std::exception& e)
    {
        dnapi::throw_napi_error(info.Env(), e);
    }
    return info.Env().Undefined();
}
std::string BinaryParamsWrapper::fmt_string()
{
    std::string result;
    if(this->params.at(0)==static_cast<uint64_t>(BinaryData::Type::UTF8))
    {
        result = "UTF8";
    }
    else if(this->params.at(0)==static_cast<uint64_t>(BinaryData::Type::Binary))
    {
        result = "Binary";
    }
    else if(this->params.at(0)==static_cast<uint64_t>(BinaryData::Type::Hex))
    {
        result = std::format("Hex:{}", this->params.at(1)?"upper":"lower");
    }
    else if(this->params.at(0)==static_cast<uint64_t>(BinaryData::Type::Base64))
    {
        if(params.at(0) == '+' && params.at(1) == '/' && params.at(2) == '=')
        {
            result = "Base64";
        }
        else
        {
            result = std::format("Base64:{}{}{}", this->params.at(1), this->params.at(2), this->params.at(3));
        }
    }
    return result;
}
Napi::Value BinaryParamsWrapper::fmt_string(const Napi::CallbackInfo& info)
{
    try
    {
        return Napi::String::New(info.Env(), this->fmt_string());
    }
    catch (const std::exception& e)
    {
        dnapi::throw_napi_error(info.Env(), e);
    }
    return info.Env().Undefined();
}
BinaryParams BinaryParamsWrapper::toBinaryParams()
{
    return BinaryParams{this->params};
}
Napi::Object BinaryParamsWrapper::registerClass(Napi::Env env, Napi::Object exports)
{
    Napi::Function func = DefineClass(env, "BinaryParams", {
        InstanceMethod("fmtString", &BinaryParamsWrapper::fmt_string),
        InstanceMethod("fmtBinary", &BinaryParamsWrapper::fmt_binary),
    });
    BinaryParamsWrapper::constructor = Napi::Persistent(func);
    BinaryParamsWrapper::constructor.SuppressDestruct();
    exports.Set("BinaryParams", func);
    return exports;
}