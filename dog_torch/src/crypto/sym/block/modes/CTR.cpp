#include "crypto/sym/block/modes/CTR.h"

namespace NSROOT = dog_torch::crypto::sym::block::mode;
using dog_torch::serialize::BinaryData;
using dog_torch::serialize::tlv::Value;

NSROOT::CTR::CTR(const BinaryData& iv, const padding::Padding& padding) : Mode(padding), iv_(iv) {};
NSROOT::CTR::CTR(const BinaryData& iv, uint64_t shift, const padding::Padding& padding) : Mode(padding), iv_(iv), shift_(shift) {};
NSROOT::CTR::CTR(const CTR& other) : Mode(other)
{
    iv_ = other.iv_;
    shift_ = other.shift_;
}
NSROOT::CTR& NSROOT::CTR::operator=(const CTR& other)
{
    Mode::operator=(other);
    iv_ = other.iv_;
    shift_ = other.shift_;
    return *this;
}
NSROOT::CTR::CTR(CTR&& other) noexcept : Mode(std::move(other))
{
    iv_ = std::move(other.iv_);
    shift_ = other.shift_;
}
NSROOT::CTR& NSROOT::CTR::operator=(CTR&& other) noexcept
{
    if (this ==&other) return *this;
    Mode::operator=(std::move(other));
    iv_ = std::move(other.iv_);
    shift_ = other.shift_;
    return *this;
}

std::unique_ptr<NSROOT::Mode> NSROOT::CTR::clone() const
{
    return std::make_unique<CTR>(*this);
}
const NSROOT::Config& NSROOT::CTR::params_config()
{
    static const Config config = Config("CTR", {
        {"iv",ParamType::Binary},
        {"shift",ParamType::UInt64}
        });
    return config;
}
NSROOT::Config NSROOT::CTR::config() const
{
    return params_config();
}
std::string NSROOT::CTR::fmt_string() const
{
    if (this->shift_ == 0)
    {
        if (this->padding_->fmt_string() != "NoPadding")
        {
            return std::format("CTR<{}>", this->padding_->fmt_string());
        }
        else
        {
            return "CTR";
        }
    }
    else
    {
        if (this->padding_->fmt_string() != "NoPadding")
        {
            return std::format("CTR<{}B,{}>", this->shift_, this->padding_->fmt_string());
        }
        else
        {
            return std::format("CTR<{}B>", this->shift_);
        }
    }
}
Value NSROOT::CTR::serialize() const
{
    using dog_torch::serialize::tlv::MIBString;
    using dog_torch::math::number::Integer64;
    Value total = static_cast<Mode>(*this).serialize();
    total.to_array()[0] = MIBString{ this->config().name };
    Value params = std::unordered_map<MIBString, Value>{};
    params.to_object()[MIBString{ "shift" }] = Value{ Integer64{this->shift_} };
    params.to_object()[MIBString{ "iv" }] = Value{ this->iv_.get_data() };
    total.to_array().push_back(params);
    return total;
}
bool NSROOT::CTR::set_uint64_param(const std::string& param, uint64_t value)
{
    return false;
}
bool NSROOT::CTR::set_string_param(const std::string& param, const std::string& value)
{
    return false;
}
bool NSROOT::CTR::set_binary_param(const std::string& param, const BinaryData& value)
{
    if (param == "iv")
    {
        this->iv_ = value;
        return true;
    }
    return false;
}
bool NSROOT::CTR::check(const algorithm::Algorithm& algorithm) const
{
    return this->iv_.size() >= algorithm.get_block_size();
}

NSROOT::crypt_func NSROOT::CTR::get_mult_encrypt() const
{
    return [this](const BinaryData& p, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
        {
            return CTR::encrypt(p, k, a, this->padding_->get_padding(), this->iv_, this->shift_);
        };
}
NSROOT::crypt_func NSROOT::CTR::get_mult_decrypt() const
{
    return [this](const BinaryData& c, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
        {
            return CTR::decrypt(c, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_);
        };
}

NSROOT::stream_crypt_func NSROOT::CTR::get_stream_encrypt() const
{
    return [this](std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CTR::encrypt_stream(p, t, c, k, a, this->padding_->get_padding(), this->iv_, this->shift_);
        };
}
NSROOT::stream_crypt_func NSROOT::CTR::get_stream_decrypt() const
{
    return [this](std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CTR::decrypt_stream(c, t, p, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_);
        };
}

NSROOT::streamp_crypt_func NSROOT::CTR::get_streamp_encrypt() const
{
    return [this](PauseableChannel& pc, std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CTR::encryptp_stream(pc, p, t, c, k, a, this->padding_->get_padding(), this->iv_, this->shift_);
        };
}
NSROOT::streamp_crypt_func NSROOT::CTR::get_streamp_decrypt() const
{
    return [this](PauseableChannel& pc, std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CTR::decryptp_stream(pc, c, t, p, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_);
        };
}

void NSROOT::CTR::update_iv_self(BinaryData& iv)
{
    if (iv.size() == 0) return;
    uint64_t count = 0;
    uint64_t size = iv.size() / 2;
    if (size == 0) size = 1;
    else if (size > 8) size = 8;
    memcpy(((uint8_t*)&count) + (8 - size), iv.data_ptr() + (iv.size() - size), size);
    if constexpr (std::endian::native == std::endian::little)
    {
        count = std::byteswap(count);
    }
    count++;
    if constexpr (std::endian::native == std::endian::little)
    {
        count = std::byteswap(count);
    }
    memcpy(iv.data_ptr() + (iv.size() - size), ((uint8_t*)&count) + (8 - size), size);
}

#define CTR_INIT \
uint64_t block_size = algorithm.get_block_size(); \
uint64_t key_size = algorithm.get_key_size(); \
BinaryData iv_ = iv.sub_bytes_len(0,block_size);\
shift = shift == 0 ? block_size : shift;\
const BinaryData& key = available_key; \
using dog_torch::serialize::stream::read_bytes;\
using dog_torch::serialize::stream::read_bits;\
using dog_torch::serialize::stream::write_bits;

#define CTR_EN_INIT \
CTR_INIT \
algorithm::block_cryption_func block_encryption = algorithm.get_encrypt();\
algorithm::block_self_cryption_func block_self_encryption = algorithm.get_encrypt_self();

BinaryData NSROOT::CTR::encrypt(
    const BinaryData& plain,
    const BinaryData& available_key,
    const algorithm::Algorithm& algorithm, padding::padding_func padding, const BinaryData& iv, uint64_t shift)
{
    CTR_EN_INIT;

    BinaryData crypt;
    crypt.reserve(plain.size());

    BinaryData buffer0, buffer1;
    uint64_t now = 0, num = 0;
    while (read_bytes(plain, plain.size(), now, buffer0, shift, num) == shift)
    {
        buffer1 = block_encryption(iv_, block_size, key, key_size);
        buffer0 ^= buffer1;
        crypt += buffer0.sub_bytes_len(0, shift);
        CTR::update_iv_self(iv_);
    }
    buffer1 = block_encryption(iv_, block_size, key, key_size);
    padding(buffer0, shift);
    buffer0 ^= buffer1.sub_bytes_len(0, buffer0.size());
    crypt += buffer0;
    return crypt;
}
BinaryData NSROOT::CTR::decrypt(
    const BinaryData& crypt,
    const BinaryData& available_key,
    const algorithm::Algorithm& algorithm, padding::padding_func unpadding, const BinaryData& iv, uint64_t shift)
{
    CTR_EN_INIT;

    BinaryData plain;
    plain.reserve(crypt.size());

    BinaryData buffer0, buffer1;
    uint64_t now = 0, num = 0;
    while (read_bytes(crypt, crypt.size(), now, buffer0, shift, num) == shift&& now < crypt.size())
    {
        buffer1 = block_encryption(iv_, block_size, key, key_size);
        buffer0 ^= buffer1;
        plain += buffer0.sub_bytes_len(0, shift);
        CTR::update_iv_self(iv_);
    }
    buffer1 = block_encryption(iv_, block_size, key, key_size);
    buffer0 ^= buffer1.sub_bytes_len(0, num);
    unpadding(buffer0, shift);
    plain += buffer0;
    return plain;
}

void NSROOT::CTR::encrypt_stream(
    std::istream& plain, uint64_t total, std::ostream& crypt,
    const BinaryData& available_key,
    const algorithm::Algorithm& algorithm, padding::padding_func padding, const BinaryData& iv, uint64_t shift)
{
    CTR_EN_INIT;

    BinaryData buffer0, buffer1;
    uint64_t now = 0, num = 0;
    while (read_bytes(plain, total, now, buffer0, shift, num) == shift)
    {
        buffer1 = block_encryption(iv_, block_size, key, key_size);
        buffer0 ^= buffer1;
        crypt.write(buffer0.data_stream(), shift);
        CTR::update_iv_self(iv_);
    }
    buffer1 = block_encryption(iv_, block_size, key, key_size);
    padding(buffer0, shift);
    buffer0 ^= buffer1.sub_bytes_len(0, buffer0.size());
    crypt.write(buffer0.data_stream(), buffer0.size());
    crypt.flush();
}
void NSROOT::CTR::decrypt_stream(
    std::istream& crypt, uint64_t total, std::ostream& plain,
    const BinaryData& available_key,
    const algorithm::Algorithm& algorithm, padding::padding_func unpadding, const BinaryData& iv, uint64_t shift)
{
    CTR_EN_INIT;

    BinaryData buffer0, buffer1;
    uint64_t now = 0, num = 0;
    while (read_bytes(crypt, total, now, buffer0, shift, num) == shift&& now < total)
    {
        buffer1 = block_encryption(iv_, block_size, key, key_size);
        buffer0 ^= buffer1;
        plain.write(buffer0.data_stream(), shift);
        CTR::update_iv_self(iv_);
    }
    buffer1 = block_encryption(iv_, block_size, key, key_size);
    buffer0 ^= buffer1.sub_bytes_len(0, num);
    unpadding(buffer0, shift);
    plain.write(buffer0.data_stream(), buffer0.size());
    plain.flush();
}

void NSROOT::CTR::encryptp_stream(
    PauseableChannel& pc,
    std::istream& plain, uint64_t total, std::ostream& crypt,
    const BinaryData& available_key,
    const algorithm::Algorithm& algorithm, padding::padding_func padding, const BinaryData& iv, uint64_t shift)
{
    CTR_EN_INIT;
    pc.start();
    BinaryData buffer0, buffer1;
    uint64_t now = 0, num = 0;
    while (read_bytes(plain, total, now, buffer0, shift, num) == shift)
    {
        if (pc.check_status()) break;
        buffer1 = block_encryption(iv_, block_size, key, key_size);
        buffer0 ^= buffer1;
        crypt.write(buffer0.data_stream(), shift);
        CTR::update_iv_self(iv_);
        pc.add_progress(shift * 1.0 / total);
    }
    buffer1 = block_encryption(iv_, block_size, key, key_size);
    padding(buffer0, shift);
    buffer0 ^= buffer1.sub_bytes_len(0, buffer0.size());
    crypt.write(buffer0.data_stream(), buffer0.size());
    crypt.flush();
    pc.set_progress(1.0);
    pc.stop();
}
void NSROOT::CTR::decryptp_stream(
    PauseableChannel& pc,
    std::istream& crypt, uint64_t total, std::ostream& plain,
    const BinaryData& available_key,
    const algorithm::Algorithm& algorithm, padding::padding_func unpadding, const BinaryData& iv, uint64_t shift)
{
    CTR_EN_INIT;
    pc.start();
    BinaryData buffer0, buffer1;
    uint64_t now = 0, num = 0;
    while (read_bytes(crypt, total, now, buffer0, shift, num) == shift&& now < total)
    {
        if (pc.check_status()) break;
        buffer1 = block_encryption(iv_, block_size, key, key_size);
        buffer0 ^= buffer1;
        plain.write(buffer0.data_stream(), shift);
        CTR::update_iv_self(iv_);
        pc.add_progress(shift * 1.0 / total);
    }
    buffer1 = block_encryption(iv_, block_size, key, key_size);
    buffer0 ^= buffer1.sub_bytes_len(0, num);
    unpadding(buffer0, shift);
    plain.write(buffer0.data_stream(), buffer0.size());
    plain.flush();
    pc.set_progress(1.0);
    pc.stop();
}

NSROOT::CTRb::CTRb(const BinaryData& iv, const padding::Padding& padding) : Mode(padding), iv_(iv) {};
NSROOT::CTRb::CTRb(const BinaryData& iv, uint64_t shift, const padding::Padding& padding) : Mode(padding), iv_(iv), shift_(shift) {};

NSROOT::CTRb::CTRb(const CTRb& other) : Mode(other)
{
    this->iv_ = other.iv_;
    shift_ = other.shift_;
}
NSROOT::CTRb& NSROOT::CTRb::operator=(const CTRb& other)
{
    Mode::operator=(other);
    this->iv_ = other.iv_;
    shift_ = other.shift_;
    return *this;
}
NSROOT::CTRb::CTRb(CTRb&& other) noexcept : Mode(std::move(other))
{
    this->iv_ = std::move(other.iv_);
    shift_ = other.shift_;
}
NSROOT::CTRb& NSROOT::CTRb::operator=(CTRb&& other) noexcept
{
    if (this ==&other) return *this;
    Mode::operator=(std::move(other));
    this->iv_ = std::move(other.iv_);
    shift_ = other.shift_;
    return *this;
}

std::unique_ptr<NSROOT::Mode> NSROOT::CTRb::clone() const
{
    return std::make_unique<CTRb>(*this);
}
const NSROOT::Config& NSROOT::CTRb::params_config()
{
    static const Config config = Config("CTRb", {
        {"iv",ParamType::Binary},
        {"shift",ParamType::UInt64}
        });
    return config;
}
NSROOT::Config NSROOT::CTRb::config() const
{
    return params_config();
}
std::string NSROOT::CTRb::fmt_string() const
{
    if (this->shift_ == 0)
    {
        if (this->padding_->fmt_string() != "NoPadding")
        {
            return std::format("CTR<{}>", this->padding_->fmt_string());
        }
        else
        {
            return "CTR";
        }
    }
    else
    {
        if (this->padding_->fmt_string() != "NoPadding")
        {
            return std::format("CTR<{}b,{}>", this->shift_, this->padding_->fmt_string());
        }
        else
        {
            return std::format("CTR<{}b>", this->shift_);
        }
    }
}
Value NSROOT::CTRb::serialize() const
{
    using dog_torch::serialize::tlv::MIBString;
    using dog_torch::math::number::Integer64;
    Value total = static_cast<Mode>(*this).serialize();
    total.to_array()[0] = MIBString{ this->config().name };
    Value params = std::unordered_map<MIBString, Value>{};
    params.to_object()[MIBString{ "shift" }] = Value{ Integer64{this->shift_} };
    params.to_object()[MIBString{ "iv" }] = Value{ this->iv_.get_data() };
    total.to_array().push_back(params);
    return total;
}
bool NSROOT::CTRb::set_uint64_param(const std::string& param, uint64_t value)
{
    if (param == "shift")
    {
        this->shift_ = value;
        return true;
    }
    return false;
}
bool NSROOT::CTRb::set_string_param(const std::string& param, const std::string& value)
{
    return false;
}
bool NSROOT::CTRb::set_binary_param(const std::string& param, const BinaryData& value)
{
    if (param == "iv")
    {
        this->iv_ = value;
        return true;
    }
    return false;
}
bool NSROOT::CTRb::check(const algorithm::Algorithm& algorithm) const
{
    if (this->iv_.size() < algorithm.get_block_size())
    {
        return false;
    }
    return true;
}

NSROOT::crypt_func NSROOT::CTRb::get_mult_encrypt() const
{
    if (this->shift_ % 8 == 0)
    {
        return [this](const BinaryData& p, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
            {
                return CTR::encrypt(p, k, a, this->padding_->get_padding(), this->iv_, this->shift_ / 8);
            };
    }
    return [this](const BinaryData& p, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
        {
            return CTRb::encrypt(p, k, a, this->iv_, this->shift_);
        };
}
NSROOT::crypt_func NSROOT::CTRb::get_mult_decrypt() const
{
    if (this->shift_ % 8 == 0)
    {
        return [this](const BinaryData& c, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
            {
                return CTR::decrypt(c, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_ / 8);
            };
    }
    return [this](const BinaryData& p, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
        {
            return CTRb::decrypt(p, k, a, this->iv_, this->shift_);
        };
}

NSROOT::stream_crypt_func NSROOT::CTRb::get_stream_encrypt() const
{
    if (this->shift_ % 8 == 0)
    {
        return [this](std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
            {
                return CTR::encrypt_stream(p, t, c, k, a, this->padding_->get_padding(), this->iv_, this->shift_ / 8);
            };
    }
    return [this](std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CTRb::encrypt_stream(p, t, c, k, a, this->iv_, this->shift_);
        };
}
NSROOT::stream_crypt_func NSROOT::CTRb::get_stream_decrypt() const
{
    if (this->shift_ % 8 == 0)
    {
        return [this](std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
            {
                return CTR::decrypt_stream(c, t, p, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_ / 8);
            };
    }
    return [this](std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CTRb::decrypt_stream(c, t, p, k, a, this->iv_, this->shift_);
        };
}

NSROOT::streamp_crypt_func NSROOT::CTRb::get_streamp_encrypt() const
{
    if (this->shift_ % 8 == 0)
    {
        return [this](PauseableChannel& pc, std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
            {
                return CTR::encryptp_stream(pc, p, t, c, k, a, this->padding_->get_padding(), this->iv_, this->shift_ / 8);
            };
    }
    return [this](PauseableChannel& pc, std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CTRb::encryptp_stream(pc, p, t, c, k, a, this->iv_, this->shift_);
        };

}
NSROOT::streamp_crypt_func NSROOT::CTRb::get_streamp_decrypt() const
{
    if (this->shift_ % 8 == 0)
    {
        return [this](PauseableChannel& pc, std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
            {
                return CTR::decryptp_stream(pc, c, t, p, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_ / 8);
            };
    }
    return [this](PauseableChannel& pc, std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CTRb::decryptp_stream(pc, c, t, p, k, a, this->iv_, this->shift_);
        };
}

BinaryData NSROOT::CTRb::encrypt(
    const BinaryData& plain,
    const BinaryData& available_key,
    const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift)
{
    CTR_EN_INIT;

    BinaryData crypt;
    crypt.reserve(plain.size());

    BinaryData buffer0, buffer1;
    uint64_t now = 0, num = 0;
    uint8_t write_byte_buffer = 0, read_now_bit = 0, write_now_bit = 0;
    while (read_bits(plain, plain.size(), now, read_now_bit, buffer0, shift, num) == shift)
    {
        buffer1 = block_encryption(iv_, block_size, key, key_size);
        buffer0 ^= buffer1;
        write_bits(crypt, write_byte_buffer, write_now_bit, shift, buffer0, num);
        CTR::update_iv_self(iv_);
    }
    buffer1 = block_encryption(iv_, block_size, key, key_size);
    buffer0 ^= buffer1;
    write_bits(crypt, write_byte_buffer, write_now_bit, shift, buffer0, num);
    return crypt;
}
BinaryData NSROOT::CTRb::decrypt(
    const BinaryData& crypt,
    const BinaryData& available_key,
    const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift)
{
    CTR_EN_INIT;

    BinaryData plain;
    plain.reserve(crypt.size());

    BinaryData buffer0, buffer1;
    uint64_t now = 0, num = 0;
    uint8_t write_byte_buffer = 0, read_now_bit = 0, write_now_bit = 0;
    while (read_bits(crypt, crypt.size(), now, read_now_bit, buffer0, shift, num) == shift && now < crypt.size())
    {
        buffer1 = block_encryption(iv_, block_size, key, key_size);
        buffer0 ^= buffer1;
        write_bits(plain, write_byte_buffer, write_now_bit, shift, buffer0, num);
        CTR::update_iv_self(iv_);
    }
    buffer1 = block_encryption(iv_, block_size, key, key_size);
    buffer0 ^= buffer1;
    write_bits(plain, write_byte_buffer, write_now_bit, shift, buffer0, num);
    return plain;
}

void NSROOT::CTRb::encrypt_stream(
    std::istream& plain, uint64_t total, std::ostream& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift)
{
    CTR_EN_INIT;

    BinaryData buffer0, buffer1;
    uint64_t now = 0, num = 0;
    uint8_t write_byte_buffer = 0, read_now_bit = 0, write_now_bit = 0;
    while (read_bits(plain, total, now, read_now_bit, buffer0, shift, num) == shift)
    {
        buffer1 = block_encryption(iv_, block_size, key, key_size);
        buffer0 ^= buffer1;
        write_bits(crypt, write_byte_buffer, write_now_bit, shift, buffer0, num);
        CTR::update_iv_self(iv_);
    }
    buffer1 = block_encryption(iv_, block_size, key, key_size);
    buffer0 ^= buffer1;
    write_bits(crypt, write_byte_buffer, write_now_bit, shift, buffer0, num);
    crypt.flush();
}
void NSROOT::CTRb::decrypt_stream(
    std::istream& crypt, uint64_t total, std::ostream& plain, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift)
{
    CTR_EN_INIT;

    BinaryData buffer0, buffer1;
    uint64_t now = 0, num = 0;
    uint8_t write_byte_buffer = 0, read_now_bit = 0, write_now_bit = 0;
    while (read_bits(crypt, total, now, read_now_bit, buffer0, shift, num) == shift && now < total)
    {
        buffer1 = block_encryption(iv_, block_size, key, key_size);
        buffer0 ^= buffer1;
        write_bits(plain, write_byte_buffer, write_now_bit, shift, buffer0, num);
        CTR::update_iv_self(iv_);
    }
    buffer1 = block_encryption(iv_, block_size, key, key_size);
    buffer0 ^= buffer1;
    write_bits(plain, write_byte_buffer, write_now_bit, shift, buffer0, num);
    plain.flush();
}

void NSROOT::CTRb::encryptp_stream(
    PauseableChannel& pc, 
    std::istream& plain, uint64_t total, std::ostream& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift)
{
    CTR_EN_INIT;
    pc.start();
    BinaryData buffer0, buffer1;
    uint64_t now = 0, num = 0;
    uint8_t write_byte_buffer = 0, read_now_bit = 0, write_now_bit = 0;
    while (read_bits(plain, total, now, read_now_bit, buffer0, shift, num) == shift)
    {
        if (pc.check_status()) break;
        buffer1 = block_encryption(iv_, block_size, key, key_size);
        buffer0 ^= buffer1;
        write_bits(crypt, write_byte_buffer, write_now_bit, shift, buffer0, num);
        CTR::update_iv_self(iv_);
        pc.add_progress(shift * 1.0 / (total * 8));
    }
    buffer1 = block_encryption(iv_, block_size, key, key_size);
    buffer0 ^= buffer1;
    write_bits(crypt, write_byte_buffer, write_now_bit, shift, buffer0, num);
    crypt.flush();
    pc.set_progress(1.0);
    pc.stop();
}
void NSROOT::CTRb::decryptp_stream(
    PauseableChannel& pc, 
    std::istream& crypt, uint64_t total, std::ostream& plain, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift)
{
    CTR_EN_INIT;
    pc.start();
    BinaryData buffer0, buffer1;
    uint64_t now = 0, num = 0;
    uint8_t write_byte_buffer = 0, read_now_bit = 0, write_now_bit = 0;
    while (read_bits(crypt, total, now, read_now_bit, buffer0, shift, num) == shift && now < total)
    {
        if (pc.check_status()) break;
        buffer1 = block_encryption(iv_, block_size, key, key_size);
        buffer0 ^= buffer1;
        write_bits(plain, write_byte_buffer, write_now_bit, shift, buffer0, num);
        CTR::update_iv_self(iv_);
        pc.add_progress(shift * 1.0 / (total * 8));
    }
    buffer1 = block_encryption(iv_, block_size, key, key_size);
    buffer0 ^= buffer1;
    write_bits(plain, write_byte_buffer, write_now_bit, shift, buffer0, num);
    plain.flush();
    pc.set_progress(1.0);
    pc.stop();
}
