#include "crypto/sym/block/modes/CBC.h"

namespace NSROOT = dog_torch::crypto::sym::block::mode;
using dog_torch::serialize::BinaryData;
using Value = dog_torch::serialize::tlv::Value;
using dog_torch::utils::from_c_str;

using dog_torch::utils::from_uint64;
using dog_torch::utils::array_to_view;

constexpr auto ERROR_ALLOW_SIZE_OR_PADDING = from_c_str("CBC: plain size must be multiple of block size when NoPadding");
constexpr auto ERROR_CRYPT_ALLOW_SIZE = from_c_str("CBC: crypt size must be multiple of block size");

NSROOT::CBC::CBC(const BinaryData& iv, const padding::Padding& padding) : iv_(iv), Mode(padding) {}

NSROOT::CBC::CBC(const CBC& other) : Mode(other)
{
    this->padding_ = other.padding_->clone();
    this->iv_ = other.iv_;
}
NSROOT::CBC& NSROOT::CBC::operator=(const CBC& other)
{
    Mode::operator=(other);
    this->padding_ = other.padding_->clone();
    this->iv_ = other.iv_;
    return *this;
}
NSROOT::CBC::CBC(CBC&& other) noexcept : Mode(std::move(other))
{
    this->padding_ = std::move(other.padding_);
    this->iv_ = std::move(other.iv_);
}
NSROOT::CBC& NSROOT::CBC::operator=(CBC&& other) noexcept
{
    if (this ==&other) return *this;
    Mode::operator=(std::move(other));
    this->padding_ = std::move(other.padding_);
    this->iv_ = std::move(other.iv_);
    return *this;
}

std::unique_ptr<NSROOT::Mode> NSROOT::CBC::clone() const
{
    return std::make_unique<CBC>(*this);
}
const NSROOT::Config& NSROOT::CBC::params_config()
{
    static const Config config = Config("CBC", {
        {"iv",ParamType::Binary}
        });
    return config;
}
NSROOT::Config NSROOT::CBC::config() const
{
    return params_config();
}
std::string NSROOT::CBC::fmt_string() const
{
    return std::format("CBC<{}>", this->padding_->fmt_string());
}
Value NSROOT::CBC::serialize() const
{
    using dog_torch::serialize::tlv::MIBString;
    auto total = static_cast<Mode>(*this).serialize();
    Value params = std::unordered_map<MIBString, Value>{};
    params.to_object()[MIBString{ "iv" }] = Value{ this->iv_.get_data() };
    total.to_array().push_back(params);
    return total;
}
bool NSROOT::CBC::set_uint64_param(const std::string& param, uint64_t value)
{
    return false;
}
bool NSROOT::CBC::set_string_param(const std::string& param, const std::string& value)
{
    return false;
}
bool NSROOT::CBC::set_binary_param(const std::string& param, const BinaryData& value)
{
    if (param == "iv")
    {
        this->iv_ = value;
        return true;
    }
    return false;
}
bool NSROOT::CBC::check(const algorithm::Algorithm& algorithm) const
{
    if (this->iv_.size() < algorithm.get_block_size())
    {
        return false;
    }
    return true;
}

NSROOT::crypt_func NSROOT::CBC::get_mult_encrypt() const
{
    return [this](const BinaryData& p, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
        {
            return CBC::encrypt(p, k, a, this->padding_->get_padding(), this->iv_);
        };
}
NSROOT::crypt_func NSROOT::CBC::get_mult_decrypt() const
{
    return [this](const BinaryData& c, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
        {
            return CBC::decrypt(c, k, a, this->padding_->get_unpadding(), this->iv_);
        };
}

NSROOT::stream_crypt_func NSROOT::CBC::get_stream_encrypt() const
{
    return [this](std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CBC::encrypt_stream(p, t, c, k, a, this->padding_->get_padding(), this->iv_);
        };
}
NSROOT::stream_crypt_func NSROOT::CBC::get_stream_decrypt() const
{
    return [this](std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CBC::decrypt_stream(c, t, p, k, a, this->padding_->get_unpadding(), this->iv_);
        };
}

NSROOT::streamp_crypt_func NSROOT::CBC::get_streamp_encrypt() const
{
    return [this](PauseableChannel& pc, std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CBC::encryptp_stream(pc, p, t, c, k, a, this->padding_->get_padding(), this->iv_);
        };
}
NSROOT::streamp_crypt_func NSROOT::CBC::get_streamp_decrypt() const
{
    return [this](PauseableChannel& pc, std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CBC::decryptp_stream(pc, c, t, p, k, a, this->padding_->get_padding(), this->iv_);
        };
}

#define CBC_INIT \
uint64_t block_size = algorithm.get_block_size(); \
uint64_t key_size = algorithm.get_key_size(); \
BinaryData iv_ = iv.sub_bytes_len(0,block_size);\
const BinaryData& key = available_key; \
using dog_torch::serialize::stream::read_bytes;

#define CBC_EN_INIT \
CBC_INIT \
algorithm::block_cryption_func block_encryption = algorithm.get_encrypt();\
algorithm::block_self_cryption_func block_self_encryption = algorithm.get_encrypt_self();

#define CBC_DE_INIT \
CBC_INIT \
algorithm::block_cryption_func block_decryption = algorithm.get_decrypt();\
algorithm::block_self_cryption_func block_self_decryption = algorithm.get_decrypt_self();

BinaryData NSROOT::CBC::encrypt(
    const BinaryData& plain, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func padding, const BinaryData& iv)
{
    CBC_EN_INIT;

    BinaryData buffer;
    padding(buffer, block_size);
    if (plain.size() % block_size != 0 && buffer.size() < block_size) 
        throw DOG_EXCEPTION(array_to_view(ERROR_ALLOW_SIZE_OR_PADDING));

    BinaryData crypt;
    crypt.reserve(((1 + (plain.size() - 1) / block_size) * block_size));

    uint64_t now = 0;
    uint64_t buffer_size = 0;
    while (read_bytes(plain, plain.size(), now, buffer, block_size, buffer_size) == block_size)
    {
        buffer ^= iv_;
        block_self_encryption(buffer, block_size, available_key, key_size);
        crypt += buffer;
        iv_ = buffer;
    }
    padding(buffer, block_size);
    buffer ^= iv_;
    block_self_encryption(buffer, block_size, available_key, key_size);
    crypt += buffer;
    return crypt;
}

BinaryData NSROOT::CBC::decrypt(
    const BinaryData& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func unpadding, const BinaryData& iv)
{
    CBC_DE_INIT;

    if (crypt.size() % block_size != 0)
        throw DOG_EXCEPTION(array_to_view(ERROR_CRYPT_ALLOW_SIZE));
    BinaryData plain;
    plain.reserve(crypt.size());

    BinaryData buffer0, buffer1;
    uint64_t now = 0;
    uint64_t buffer_size = 0;
    while (read_bytes(crypt, crypt.size(), now, buffer0, block_size, buffer_size) == block_size && now < crypt.size())
    {
        buffer1 = buffer0;
        block_self_decryption(buffer0, block_size, key, key_size);
        buffer0 ^= iv_;
        plain += buffer0;
        iv_ = buffer1;
    }
    block_self_decryption(buffer0, block_size, key, key_size);
    buffer0 ^= iv_;
    unpadding(buffer0, block_size);
    plain += buffer0;
    return plain;
}

void NSROOT::CBC::encrypt_stream(
    std::istream& plain, uint64_t total, std::ostream& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func padding, const BinaryData& iv)
{
    CBC_EN_INIT;

    BinaryData buffer;
    padding(buffer, block_size);
    if (total % block_size != 0 && buffer.size() < block_size) 
        throw DOG_EXCEPTION(array_to_view(ERROR_ALLOW_SIZE_OR_PADDING));
    uint64_t now = 0;
    uint64_t buffer_size = 0;
    while (read_bytes(plain, total, now, buffer, block_size, buffer_size) == block_size)
    {
        buffer ^= iv_;
        block_self_encryption(buffer, block_size, key, key_size);
        crypt.write(buffer.data_stream(), block_size);
        iv_ = buffer;
    }
    padding(buffer, block_size);
    block_self_encryption(buffer, block_size, key, key_size);
    buffer ^= iv_;
    crypt.write(buffer.data_stream(), block_size);
    crypt.flush();
}

void NSROOT::CBC::decrypt_stream(
    std::istream& crypt, uint64_t total, std::ostream& plain, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func unpadding, const BinaryData& iv)
{
    CBC_DE_INIT;

    if (total % block_size != 0) 
        throw DOG_EXCEPTION(array_to_view(ERROR_CRYPT_ALLOW_SIZE));
    BinaryData buffer0, buffer1;
    uint64_t now = 0;
    uint64_t buffer_size = 0;
    while (read_bytes(crypt, total, now, buffer0, block_size, buffer_size) == block_size&& now < total)
    {
        buffer1 = buffer0;
        block_self_decryption(buffer0, block_size, key, key_size);
        buffer0 ^= iv_;
        plain.write(buffer0.data_stream(), block_size);
        iv_ = buffer1;
    }
    buffer0 ^= iv_;
    block_self_decryption(buffer0, block_size, key, key_size);
    unpadding(buffer0, block_size);
    plain.write(buffer0.data_stream(), buffer0.size());
    plain.flush();
}

void NSROOT::CBC::encryptp_stream(
    PauseableChannel& pc, 
    std::istream& plain, uint64_t total, std::ostream& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func padding, const BinaryData& iv)
{
    CBC_EN_INIT;
    
    pc.start();
    BinaryData buffer;
    padding(buffer, block_size);
    if (total % block_size != 0 && buffer.size() < block_size) 
        throw DOG_EXCEPTION(array_to_view(ERROR_ALLOW_SIZE_OR_PADDING));
    uint64_t now = 0;
    uint64_t buffer_size = 0;
    while (read_bytes(plain, total, now, buffer, block_size, buffer_size) == block_size)
    {
        if (pc.check_status()) break;
        block_self_encryption(buffer, block_size, key, key_size);
        buffer ^= iv_;
        crypt.write(buffer.data_stream(), block_size);
        iv_ = buffer;
        pc.add_progress(block_size * 1.0 / total);
    }
    padding(buffer, block_size);
    block_self_encryption(buffer, block_size, key, key_size);
    buffer ^= iv_;
    crypt.write(buffer.data_stream(), block_size);
    crypt.flush();
    pc.set_progress(1.0);
    pc.stop();
}

void NSROOT::CBC::decryptp_stream(
    PauseableChannel& pc, 
    std::istream& crypt, uint64_t total, std::ostream& plain, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func unpadding, const BinaryData& iv)
{
    CBC_DE_INIT;

    if (total % block_size != 0) 
        throw DOG_EXCEPTION(array_to_view(ERROR_CRYPT_ALLOW_SIZE));
    pc.start();
    BinaryData buffer0, buffer1;
    uint64_t now = 0;
    uint64_t buffer_size = 0;
    while (read_bytes(crypt, total, now, buffer0, block_size, buffer_size) == block_size&& now < total)
    {
        if (pc.check_status()) break;
        buffer1 = buffer0;
        block_self_decryption(buffer0, block_size, key, key_size);
        buffer0 ^= iv_;
        plain.write(buffer0.data_stream(), block_size);
        iv_ = buffer1;
        pc.add_progress(block_size * 1.0 / total);
    }
    block_self_decryption(buffer0, block_size, key, key_size);
    buffer0 ^= iv_;
    unpadding(buffer0, block_size);
    plain.write(buffer0.data_stream(), block_size);
    plain.flush();
    pc.set_progress(1.0);
    pc.stop();
}


#undef CBC_DE_INIT
#undef CBC_EN_INIT
#undef CBC_INIT