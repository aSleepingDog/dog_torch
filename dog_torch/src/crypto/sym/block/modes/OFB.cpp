#include "crypto/sym/block/modes/OFB.h"

namespace NSROOT = dog_torch::crypto::sym::block::mode;
using dog_torch::serialize::BinaryData;
using dog_torch::serialize::tlv::Value;

NSROOT::OFB::OFB(const BinaryData& iv, const padding::Padding& padding) : Mode(padding), iv_(iv) {}
NSROOT::OFB::OFB(const BinaryData& iv, uint64_t shift, const padding::Padding& padding) : Mode(padding), iv_(iv), shift_(shift) {};

NSROOT::OFB::OFB(const OFB& other) : Mode(other)
{
    this->iv_ = other.iv_;
    this->padding_ = other.padding_->clone();
}
NSROOT::OFB& NSROOT::OFB::operator=(const OFB& other)
{
    Mode::operator=(other);
    this->iv_ = other.iv_;
    this->padding_ = other.padding_->clone();
    return *this;
}
NSROOT::OFB::OFB(OFB&& other) noexcept : Mode(std::move(other))
{
    this->iv_ = std::move(other.iv_);
    this->padding_ = std::move(other.padding_);
}
NSROOT::OFB& NSROOT::OFB::operator=(OFB&& other) noexcept
{
    if (this ==&other) return *this;
    Mode::operator=(std::move(other));
    this->iv_ = std::move(other.iv_);
    this->padding_ = std::move(other.padding_);
    return *this;
}

std::unique_ptr<NSROOT::Mode> NSROOT::OFB::clone() const
{
    return std::make_unique<OFB>(*this);
}
const NSROOT::Config& NSROOT::OFB::params_config()
{
    static const Config config = Config("OFB", {
        {"iv",ParamType::Binary},
        {"shift",ParamType::UInt64}
        });
    return config;
}
NSROOT::Config NSROOT::OFB::config() const
{
    return params_config();
}
std::string NSROOT::OFB::fmt_string() const
{
    if (this->shift_ == 0)
    {
        if (this->padding_->fmt_string() != "NoPadding")
        {
            return std::format("OFB<{}>", this->padding_->fmt_string());
        }
        else
        {
            return "OFB";
        }
    }
    else
    {
        if (this->padding_->fmt_string() != "NoPadding")
        {
            return std::format("OFB<{}B,{}>", this->shift_, this->padding_->fmt_string());
        }
        else
        {
            return std::format("OFB<{}B>", this->shift_);
        }
    }
}
Value NSROOT::OFB::serialize() const
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
bool NSROOT::OFB::set_uint64_param(const std::string& param, uint64_t value)
{
    return false;
}
bool NSROOT::OFB::set_string_param(const std::string& param, const std::string& value)
{
    return false;
}
bool NSROOT::OFB::set_binary_param(const std::string& param, const BinaryData& value)
{
    if (param == "iv")
    {
        this->iv_ = value;
        return true;
    }
    return false;
}
bool NSROOT::OFB::check(const algorithm::Algorithm& algorithm) const
{
    if (this->iv_.size() < algorithm.get_block_size() || this->shift_ > algorithm.get_block_size())
    {
        return false;
    }
    return true;
}

NSROOT::crypt_func NSROOT::OFB::get_mult_encrypt() const
{
    return [this](const BinaryData& p, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
        {
            return OFB::encrypt(p, k, a, this->padding_->get_padding(), this->iv_, this->shift_);
        };
}
NSROOT::crypt_func NSROOT::OFB::get_mult_decrypt() const
{
    return [this](const BinaryData& c, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
        {
            return OFB::decrypt(c, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_);
        };
}

NSROOT::stream_crypt_func NSROOT::OFB::get_stream_encrypt() const
{
    return [this](std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return OFB::encrypt_stream(p, t, c, k, a, this->padding_->get_padding(), this->iv_, this->shift_);
        };
}
NSROOT::stream_crypt_func NSROOT::OFB::get_stream_decrypt() const
{
    return [this](std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return OFB::decrypt_stream(c, t, p, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_);
        };
}

NSROOT::streamp_crypt_func NSROOT::OFB::get_streamp_encrypt() const
{
    return [this](PauseableChannel& pc, std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return OFB::encryptp_stream(pc, p, t, c, k, a, this->padding_->get_padding(), this->iv_, this->shift_);
        };
}
NSROOT::streamp_crypt_func NSROOT::OFB::get_streamp_decrypt() const
{
    return [this](PauseableChannel& pc, std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return OFB::decryptp_stream(pc, c, t, p, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_);
        };
}

#define OFB_INIT \
uint64_t block_size = algorithm.get_block_size(); \
uint64_t key_size = algorithm.get_key_size(); \
BinaryData iv_ = iv.sub_bytes_len(0,block_size);\
shift = shift == 0 ? block_size : shift;\
const BinaryData& key = available_key; \
using dog_torch::serialize::stream::read_bytes;\
using dog_torch::serialize::stream::read_bits;\
using dog_torch::serialize::stream::write_bits;

#define OFB_EN_INIT \
OFB_INIT \
algorithm::block_cryption_func block_encryption = algorithm.get_encrypt();\
algorithm::block_self_cryption_func block_self_encryption = algorithm.get_encrypt_self();


BinaryData NSROOT::OFB::encrypt(
    const BinaryData& plain, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func padding, const BinaryData& iv, uint64_t shift)
{
    OFB_EN_INIT;

    BinaryData crypt;
    crypt.reserve(plain.size());

    BinaryData buffer;
    uint64_t now = 0, num = 0;
    while (read_bytes(plain, plain.size(), now, buffer, shift, num) == shift)
    {
        block_self_encryption(iv_, block_size, key, key_size);
        buffer ^= iv_;
        crypt += buffer.sub_bytes_len(0, shift);
    }
    block_self_encryption(iv_, block_size, key, key_size);
    padding(buffer, shift);
    buffer ^= iv_.sub_bytes_len(0, buffer.size());
    crypt += buffer;
    return crypt;
}
BinaryData NSROOT::OFB::decrypt(
    const BinaryData& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func unpadding, const BinaryData& iv, uint64_t shift)
{
    OFB_EN_INIT;

    BinaryData plain;
    plain.reserve(crypt.size());

    BinaryData buffer;
    uint64_t now = 0, num = 0;
    while (read_bytes(crypt, crypt.size(), now, buffer, shift, num) == shift && now < crypt.size())
    {
        block_self_encryption(iv_, block_size, key, key_size);
        buffer ^= iv_;
        plain += buffer.sub_bytes_len(0, shift);;
    }
    block_self_encryption(iv_, block_size, key, key_size);
    buffer ^= iv_.sub_bytes_len(0, num);
    unpadding(buffer, shift);
    plain += buffer;
    return plain;
}

void NSROOT::OFB::encrypt_stream(
    std::istream& plain, uint64_t total, std::ostream& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func padding, const BinaryData& iv, uint64_t shift)
{
    OFB_EN_INIT;

    BinaryData buffer;
    uint64_t now = 0, num = 0;
    while (read_bytes(plain, total, now, buffer, shift, num) == shift)
    {
        block_self_encryption(iv_, block_size, key, key_size);
        buffer ^= iv_;
        crypt.write(buffer.data_stream(), shift);
    }
    block_self_encryption(iv_, block_size, key, key_size);
    padding(buffer, shift);
    buffer ^= iv_.sub_bytes_len(0, buffer.size());
    crypt.write(buffer.data_stream(), buffer.size());
    crypt.flush();
}
void NSROOT::OFB::decrypt_stream(
    std::istream& crypt, uint64_t total, std::ostream& plain, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func unpadding, const BinaryData& iv, uint64_t shift)
{
    OFB_EN_INIT;

    BinaryData buffer;
    uint64_t now = 0, num = 0;
    while (read_bytes(crypt, total, now, buffer, shift, num) == shift&& now < total)
    {
        block_self_encryption(iv_, block_size, key, key_size);
        buffer ^= iv_;
        plain.write(buffer.data_stream(), shift);
    }
    block_self_encryption(iv_, block_size, key, key_size);
    buffer ^= iv_.sub_bytes_len(0, num);
    unpadding(buffer, shift);
    plain.write(buffer.data_stream(), buffer.size());
    plain.flush();
}

void NSROOT::OFB::encryptp_stream(
    PauseableChannel& pc, 
    std::istream& plain, uint64_t total, std::ostream& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func padding, const BinaryData& iv, uint64_t shift)
{
    OFB_EN_INIT;
    pc.start();
    BinaryData buffer;
    uint64_t now = 0, num = 0;
    while (read_bytes(plain, total, now, buffer, shift, num) == shift)
    {
        if (pc.check_status()) break;
        block_self_encryption(iv_, block_size, key, key_size);
        buffer ^= iv_;
        crypt.write(buffer.data_stream(), shift);
        pc.add_progress(block_size * 1.0 / total);
    }
    block_self_encryption(iv_, block_size, key, key_size);
    padding(buffer, shift);
    buffer ^= iv_.sub_bytes_len(0, buffer.size());
    crypt.write(buffer.data_stream(), buffer.size());
    crypt.flush();
    pc.set_progress(1.0);
    pc.stop();
}
void NSROOT::OFB::decryptp_stream(
    PauseableChannel& pc, 
    std::istream& crypt, uint64_t total, std::ostream& plain, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func unpadding, const BinaryData& iv, uint64_t shift)
{
    OFB_EN_INIT;
    pc.start();
    BinaryData buffer;
    uint64_t now = 0, num = 0;
    while (read_bytes(crypt, total, now, buffer, shift, num) == shift&& now < total)
    {
        if (pc.check_status()) break;
        block_self_encryption(iv_, block_size, key, key_size);
        buffer ^= iv_;
        plain.write(buffer.data_stream(), shift);
        pc.add_progress(block_size * 1.0 / total);
    }
    block_self_encryption(iv_, block_size, key, key_size);
    buffer ^= iv_.sub_bytes_len(0, num);
    unpadding(buffer, shift);
    plain.write(buffer.data_stream(), buffer.size());
    plain.flush();
    pc.set_progress(1.0);
    pc.stop();
}


NSROOT::OFBb::OFBb(const BinaryData& iv, const padding::Padding& padding) : Mode(padding), iv_(iv) {};
NSROOT::OFBb::OFBb(const BinaryData& iv, uint64_t shift, const padding::Padding&padding) : Mode(padding), iv_(iv), shift_(shift) {};

NSROOT::OFBb::OFBb(const OFBb& other) : Mode(other)
{
    this->iv_ = other.iv_;
    this->padding_ = other.padding_->clone();
}
NSROOT::OFBb& NSROOT::OFBb::operator=(const OFBb& other)
{
    Mode::operator=(other);
    this->iv_ = other.iv_;
    this->padding_ = other.padding_->clone();
    return *this;
}
NSROOT::OFBb::OFBb(OFBb&& other) noexcept : Mode(std::move(other))
{
    this->iv_ = std::move(other.iv_);
    this->padding_ = std::move(other.padding_);
}
NSROOT::OFBb& NSROOT::OFBb::operator=(OFBb&& other) noexcept
{
    if (this == &other) return *this;
    Mode::operator=(std::move(other));
    this->iv_ = std::move(other.iv_);
    this->padding_ = std::move(other.padding_);
    return *this;
}

std::unique_ptr<NSROOT::Mode> NSROOT::OFBb::clone() const
{
    return std::make_unique<OFBb>(*this);
}
const NSROOT::Config& NSROOT::OFBb::params_config()
{
    static const Config config = Config("OFBb", {
        {"iv",ParamType::Binary},
        {"shift",ParamType::UInt64}
        });
    return config;
}
NSROOT::Config NSROOT::OFBb::config() const
{
    return params_config();
}
std::string NSROOT::OFBb::fmt_string() const
{
    if (this->shift_ == 0)
    {
        if (this->padding_->fmt_string() != "NoPadding")
        {
            return std::format("OFB<{}>", this->padding_->fmt_string());
        }
        else
        {
            return "OFB";
        }
    }
    else
    {
        if (this->padding_->fmt_string() != "NoPadding")
        {
            return std::format("OFB<{}b,{}>", this->shift_, this->padding_->fmt_string());
        }
        else
        {
            return std::format("OFB<{}b>", this->shift_);
        }
    }
}
Value NSROOT::OFBb::serialize() const
{
    using dog_torch::serialize::tlv::MIBString;
    using dog_torch::math::number::Integer64;
    Value total = std::vector<Value>{};;
    total.to_array().push_back(MIBString{ this->config().name });
    Value params = std::unordered_map<MIBString, Value>{};
    total.to_array()[0] = MIBString{ this->config().name };
    params.to_object()[MIBString{ "shift" }] = Value{ Integer64{this->shift_} };
    params.to_object()[MIBString{ "iv" }] = Value{ this->iv_.get_data() };
    total.to_array().push_back(params);
    return total;
}
bool NSROOT::OFBb::set_uint64_param(const std::string& param, uint64_t value)
{
    if (param == "shift")
    {
        this->shift_ = value;
        return true;
    }
    return false;
}
bool NSROOT::OFBb::set_string_param(const std::string& param, const std::string& value)
{
    return false;
}
bool NSROOT::OFBb::set_binary_param(const std::string& param, const BinaryData& value)
{
    if (param == "iv")
    {
        this->iv_ = value;
        return true;
    }
    return false;
}
bool NSROOT::OFBb::check(const algorithm::Algorithm& algorithm) const
{
    if (this->iv_.size() < algorithm.get_block_size())
    {
        return false;
    }
    return true;
}

NSROOT::crypt_func NSROOT::OFBb::get_mult_encrypt() const
{
    if (this->shift_ % 8 == 0)
    {
        return [this](const BinaryData& p, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
            {
                return OFB::encrypt(p, k, a, this->padding_->get_padding(), this->iv_, this->shift_ / 8);
            };
    }
    return [this](const BinaryData& p, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
        {
            return OFBb::encrypt(p, k, a, this->iv_, this->shift_);
        };
}
NSROOT::crypt_func NSROOT::OFBb::get_mult_decrypt() const
{
    if (this->shift_ % 8 == 0)
    {
        return [this](const BinaryData& c, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
            {
                return OFB::decrypt(c, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_ / 8);
            };
    }
    return [this](const BinaryData& p, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
        {
            return OFBb::decrypt(p, k, a, this->iv_, this->shift_);
        };
}

NSROOT::stream_crypt_func NSROOT::OFBb::get_stream_encrypt() const
{
    if (this->shift_ % 8 == 0)
    {
        return [this](std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
            {
                return OFB::encrypt_stream(p, t, c, k, a, this->padding_->get_padding(), this->iv_, this->shift_ / 8);
            };
    }
    return [this](std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return OFBb::encrypt_stream(p, t, c, k, a, this->iv_, this->shift_);
        };
}
NSROOT::stream_crypt_func NSROOT::OFBb::get_stream_decrypt() const
{
    if (this->shift_ % 8 == 0)
    {
        return [this](std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
            {
                return OFB::decrypt_stream(c, t, p, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_ / 8);
            };
    }
    return [this](std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return OFBb::decrypt_stream(c, t, p, k, a, this->iv_, this->shift_);
        };
}

NSROOT::streamp_crypt_func NSROOT::OFBb::get_streamp_encrypt() const
{
    if (this->shift_ % 8 == 0)
    {
        return [this](PauseableChannel& pc, std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
            {
                return OFB::encryptp_stream(pc, p, t, c, k, a, this->padding_->get_padding(), this->iv_, this->shift_ / 8);
            };
    }
    return [this](PauseableChannel& pc, std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return OFBb::encryptp_stream(pc, p, t, c, k, a, this->iv_, this->shift_);
        };

}
NSROOT::streamp_crypt_func NSROOT::OFBb::get_streamp_decrypt() const
{
    if (this->shift_ % 8 == 0)
    {
        return [this](PauseableChannel& pc, std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
            {
                return OFB::decryptp_stream(pc, c, t, p, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_ / 8);
            };
    }
    return [this](PauseableChannel& pc, std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return OFBb::decryptp_stream(pc, c, t, p, k, a, this->iv_, this->shift_);
        };
}

BinaryData NSROOT::OFBb::encrypt(
    const BinaryData& plain, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift)
{
    OFB_EN_INIT;
    BinaryData crypt;
    crypt.reserve(plain.size());

    BinaryData buffer;
    uint64_t now = 0, num = 0;
    uint8_t read_now_bit = 0, output_byte_buffer = 0, write_next_bit = 0;
    while (read_bits(plain, plain.size(), now, read_now_bit, buffer, shift, num) == shift)
    {
        block_self_encryption(iv_, block_size, key, key_size);
        buffer ^= iv_;
        write_bits(crypt, output_byte_buffer, write_next_bit, shift, buffer, num);
    }
    block_self_encryption(iv_, block_size, key, key_size);
    buffer ^= iv_;
    write_bits(crypt, output_byte_buffer, write_next_bit, shift, buffer, num);
    return crypt;
}
BinaryData NSROOT::OFBb::decrypt(
    const BinaryData& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift)
{
    OFB_EN_INIT;
    BinaryData plain;
    plain.reserve(crypt.size());

    BinaryData buffer;
    uint64_t now = 0, num = 0;
    uint8_t read_now_bit = 0, output_byte_buffer = 0, write_next_bit = 0;
    while (read_bits(crypt, crypt.size(), now, read_now_bit, buffer, shift, num) == shift)
    {
        block_self_encryption(iv_, block_size, key, key_size);
        buffer ^= iv_;
        write_bits(plain, output_byte_buffer, write_next_bit, shift, buffer, num);
    }
    block_self_encryption(iv_, block_size, key, key_size);
    buffer ^= iv_;
    write_bits(plain, output_byte_buffer, write_next_bit, shift, buffer, num);
    return plain;
}

void NSROOT::OFBb::encrypt_stream(
    std::istream& plain, uint64_t total, std::ostream& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift)
{
    OFB_EN_INIT;
    BinaryData buffer;
    uint64_t now = 0, num = 0;
    uint8_t read_now_bit = 0, output_byte_buffer = 0, write_next_bit = 0;
    while (read_bits(plain, total, now, read_now_bit, buffer, shift, num) == shift)
    {
        block_self_encryption(iv_, block_size, key, key_size);
        buffer ^= iv_;
        write_bits(crypt, output_byte_buffer, write_next_bit, shift, buffer, num);
    }
    block_self_encryption(iv_, block_size, key, key_size);
    buffer ^= iv_;
    write_bits(crypt, output_byte_buffer, write_next_bit, shift, buffer, num);
    crypt.flush();
}
void NSROOT::OFBb::decrypt_stream(
    std::istream& crypt, uint64_t total, std::ostream& plain, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift)
{
    OFB_EN_INIT;
    BinaryData buffer;
    uint64_t now = 0, num = 0;
    uint8_t read_now_bit = 0, output_byte_buffer = 0, write_next_bit = 0;
    while (read_bits(crypt, total, now, read_now_bit, buffer, shift, num) == shift)
    {
        block_self_encryption(iv_, block_size, key, key_size);
        buffer ^= iv_;
        write_bits(plain, output_byte_buffer, write_next_bit, shift, buffer, num);
    }
    block_self_encryption(iv_, block_size, key, key_size);
    buffer ^= iv_;
    write_bits(plain, output_byte_buffer, write_next_bit, shift, buffer, num);
    plain.flush();
}

void NSROOT::OFBb::encryptp_stream(
    PauseableChannel& pc, 
    std::istream& plain, uint64_t total, std::ostream& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift)
{
    OFB_EN_INIT;
    pc.start();
    BinaryData buffer;
    uint64_t now = 0, num = 0;
    uint8_t read_now_bit = 0, output_byte_buffer = 0, write_next_bit = 0;
    while (read_bits(plain, total, now, read_now_bit, buffer, shift, num) == shift)
    {
        if (pc.check_status()) break;
        block_self_encryption(iv_, block_size, key, key_size);
        buffer ^= iv_;
        write_bits(crypt, output_byte_buffer, write_next_bit, shift, buffer, num);
        pc.add_progress(shift * 1.0 / total);
    }
    block_self_encryption(iv_, block_size, key, key_size);
    buffer ^= iv_;
    write_bits(crypt, output_byte_buffer, write_next_bit, shift, buffer, num);
    crypt.flush();
    pc.set_progress(1.0);
    pc.stop();
}
void NSROOT::OFBb::decryptp_stream(
    PauseableChannel& pc, 
    std::istream& crypt, uint64_t total, std::ostream& plain, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift)
{
    OFB_EN_INIT;
    pc.start();
    BinaryData buffer;
    uint64_t now = 0, num = 0;
    uint8_t read_now_bit = 0, output_byte_buffer = 0, write_next_bit = 0;
    while (read_bits(crypt, total, now, read_now_bit, buffer, shift, num) == shift)
    {
        if (pc.check_status()) break;
        block_self_encryption(iv_, block_size, key, key_size);
        buffer ^= iv_;
        write_bits(plain, output_byte_buffer, write_next_bit, shift, buffer, num);
        pc.add_progress(shift * 1.0 / total);
    }
    block_self_encryption(iv_, block_size, key, key_size);
    buffer ^= iv_;
    write_bits(plain, output_byte_buffer, write_next_bit, shift, buffer, num);
    plain.flush();
    pc.set_progress(1.0);
    pc.stop();
}