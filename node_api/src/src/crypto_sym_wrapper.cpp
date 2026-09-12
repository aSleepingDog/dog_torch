#include "crypto_sym_wrapper.h"

dog_torch::crypto::sym::block::BlockCipher parse_block_cipher(const dog_torch::serialize::tlv::Value& value)
{
    namespace block_crypto = dog_torch::crypto::sym::block;
    namespace tlv = dog_torch::serialize::tlv;
    using dog_torch::crypto::Param;
    const auto& root_obj = value.to_object();
    if (root_obj.size() != 1 || root_obj.find(tlv::MIBString{ "Block" }) == root_obj.end())
    {
        throw std::runtime_error("head not found");
    }
    const auto& cipher_config = root_obj.at(tlv::MIBString{ "Block" }).to_array();
    const auto& algorithm_configs = cipher_config.at(0).to_array();
    std::string alg_name = algorithm_configs.at(0).to_string().string;
    uint64_t block_size = algorithm_configs.at(1).to_integer().number;
    uint64_t key_size = algorithm_configs.at(2).to_integer().number;
    auto alg_ptr = block_crypto::algorithm::create(alg_name, block_size, key_size);
    if (alg_ptr == nullptr)
    {
        throw std::runtime_error("algorithm not support");
    }
    const auto& mode_configs = cipher_config.at(1).to_array();
    std::string mode_name = mode_configs.at(0).to_string().string;
    std::string paddding_name = mode_configs.at(1).to_string().string;
    auto padding = block_crypto::padding::create(paddding_name);
    if (padding == nullptr)
    {
        throw std::runtime_error("padding not support");
    }
    std::unordered_map<std::string, Param> tar_params;
    if (mode_configs.size() > 2)
    {
        const auto& mode_args = mode_configs.at(2).to_object();
        for (const auto& [key, value] : mode_args)
        {
            std::string key_name = key.string;
            if (value.type() == tlv::Type::Bool)
            {
                tar_params[key_name] = value.to_bool();
            }
            else if (value.type() == tlv::Type::Integer)
            {
                tar_params[key_name] = value.to_integer().number;
            }
            else if (value.type() == tlv::Type::String)
            {
                tar_params[key_name] = value.to_string().string;
            }
            else if (value.type() == tlv::Type::Binary)
            {
                tar_params[key_name] = value.to_binary();
            }
        }
    }
    auto mode = block_crypto::mode::create(mode_name, *padding, tar_params);
    if (mode == nullptr)
    {
        throw std::runtime_error("mode not support");
    }
    return block_crypto::BlockCipher(*alg_ptr, *mode);
}

Napi::Value readBlockCipher(const Napi::CallbackInfo& info)
{
    using namespace dog_torch::napi;
    using namespace dog_torch::serialize::tlv;
    try
    {
        auto args0 = check_napi_args_optional<
            BinaryDataWrapper
        >(info);
        auto args1 = check_napi_args_optional<
            Napi::String
        >(info);
        Napi::Object result = Napi::Object::New(info.Env());
        Value v;
        uint64_t header_len = 0;
        if(args0)
        {
            BinaryData d = std::get<0>(args0.value()).value->data();
            auto p = d.cbegin();
            auto e = d.cend();
            v = Value::parse(p,e);
            header_len = p-d.cbegin();
        }
        else if(args1)
        {
            const auto& s = std::get<0>(args1.value()).value;
            if(!std::filesystem::exists(s))
            {
                throw std::runtime_error("file not found");
            }
            std::ifstream input(s, std::ios::binary);
            if (!input.is_open())
            {
                throw std::runtime_error("file open failed");
            }
            v = Value::parse(input);
            header_len = input.tellg();
        }
        else
        {
            throw std::runtime_error("Invalid arguments");
        }
        // std::cout << v.fmt_string() << std::endl;
        result.Set("cipher",BlockCipherWrapper::create(info,parse_block_cipher(v)));
        result.Set("length",Napi::Number::New(info.Env(),header_len));
        return result;
    }
    catch(const std::exception& e)
    {
        throw_napi_error(info.Env(), e);
    }
    return info.Env().Undefined();
}
Napi::Object registerReadBlockCipher(Napi::Env env, Napi::Object exports)
{
    exports.Set("parse", Napi::Function::New(env, readBlockCipher));
    return exports;
}

dog_torch::crypto::sym::stream::StreamCipher parse_stream_cipher(const dog_torch::serialize::tlv::Value& value)
{
    namespace block_crypto = dog_torch::crypto::sym::block;
    namespace tlv = dog_torch::serialize::tlv;
    using dog_torch::crypto::Param;
    const auto& root_obj = value.to_object();
    if (root_obj.size() != 1 || root_obj.find(tlv::MIBString{ "Stream" }) == root_obj.end())
    {
        throw std::runtime_error("head not found");
    }
    const auto& cipher_config = root_obj.at(tlv::MIBString{ "Stream" }).to_array();
    const auto& alg_p = cipher_config.at(0).to_array();
    std::string alg_name = alg_p.at(0).to_string().string;
    uint64_t effi_size = alg_p.at(1).to_integer().number;
    uint64_t key_size = alg_p.at(2).to_integer().number;
    const auto& silce = cipher_config.at(1).to_array();
    bool is_bit = silce.at(0).to_bool();
    uint64_t shift = silce.at(1).to_integer().number;
    auto alg_ptr = dog_torch::crypto::sym::stream::algorithm::create(alg_name, effi_size, key_size);
    if (alg_ptr == nullptr)
    {
        throw std::runtime_error("algorithm not support");
    }
    return dog_torch::crypto::sym::stream::StreamCipher(*alg_ptr,shift,is_bit);
}

Napi::Value readStreamCipher(const Napi::CallbackInfo& info)
{
    using namespace dog_torch::napi;
    using namespace dog_torch::serialize::tlv;
    try
    {
        auto args0 = check_napi_args_optional<
            BinaryDataWrapper
        >(info);
        auto args1 = check_napi_args_optional<
            Napi::String
        >(info);
        Napi::Object result = Napi::Object::New(info.Env());
        Value v;
        uint64_t header_len = 0;
        if(args0)
        {
            BinaryData d = std::get<0>(args0.value()).value->data();
            auto p = d.cbegin();
            auto e = d.cend();
            v = Value::parse(p,e);
            header_len = p-d.cbegin();
        }
        else if(args1)
        {
            const auto& s = std::get<0>(args1.value()).value;
            if(!std::filesystem::exists(s))
            {
                throw std::runtime_error("file not found");
            }
            std::ifstream input(s, std::ios::binary);
            if (!input.is_open())
            {
                throw std::runtime_error("file open failed");
            }
            v = Value::parse(input);
            header_len = input.tellg();
        }
        else
        {
            throw std::runtime_error("Invalid arguments");
        }
        // std::cout << v.fmt_string() << std::endl;
        result.Set("cipher",StreamCipherWrapper::create(info,parse_stream_cipher(v)));
        result.Set("length",Napi::Number::New(info.Env(),header_len));
        return result;
    }
    catch(const std::exception& e)
    {
        throw_napi_error(info.Env(), e);
    }
    return info.Env().Undefined();
}
Napi::Object registerReadStreamCipher(Napi::Env env, Napi::Object exports)
{
    exports.Set("parse", Napi::Function::New(env, readStreamCipher));
    return exports;
}