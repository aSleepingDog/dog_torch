#include "crypto/sym/block/modes/CFB.h"

namespace NSROOT = dog_torch::crypto::sym::block::mode;
using dog_torch::serialize::BinaryData;
using Value = dog_torch::serialize::tlv::Value;

NSROOT::CFB::CFB(const BinaryData& iv, uint64_t shift, const padding::Padding& padding)
    : Mode(padding.clone()),iv_(iv), shift_(shift)
{}
NSROOT::CFB::CFB(const BinaryData& iv, const padding::Padding& padding)
    : Mode(padding.clone()), iv_(iv)
{}
NSROOT::CFB::CFB(const CFB& other) : Mode(other)
{
    this->iv_ = other.iv_;
    this->shift_ = other.shift_;
}
NSROOT::CFB& NSROOT::CFB::operator=(const CFB& other)
{
    Mode::operator=(other);
    this->iv_ = other.iv_;
    this->shift_ = other.shift_;
    return *this;
}
NSROOT::CFB::CFB(CFB&& other) noexcept : Mode(std::move(other))
{
    this->iv_ = std::move(other.iv_);
    this->shift_ = std::move(other.shift_);
}
NSROOT::CFB& NSROOT::CFB::operator=(CFB&& other) noexcept
{
    if (this ==&other) return *this;
    Mode::operator=(std::move(other));
    this->iv_ = std::move(other.iv_);
    this->shift_ = std::move(other.shift_);
    return *this;
}

std::unique_ptr<NSROOT::Mode> NSROOT::CFB::clone() const
{
    return std::make_unique<CFB>(*this);
}
const NSROOT::Config& NSROOT::CFB::params_config()
{
    static const Config config = Config("CFB", {
        {"iv",ParamType::Binary},
        {"shift",ParamType::UInt64}
        });
    return config;
}
NSROOT::Config NSROOT::CFB::config() const
{
    return params_config();
}
std::string NSROOT::CFB::fmt_string() const
{
    if (this->shift_ == 0)
    {
        if (this->padding_->fmt_string() != "NoPadding")
        {
            return std::format("CFB<{}>", this->padding_->fmt_string());
        }
        else
        {
            return "CFB";
        }
    }
    else
    {
        if (this->padding_->fmt_string() != "NoPadding")
        {
            return std::format("CFB<{}B,{}>", this->shift_, this->padding_->fmt_string());
        }
        else
        {
            return std::format("CFB<{}B>", this->shift_);
        }
    }
}
Value NSROOT::CFB::serialize() const
{
    using dog_torch::serialize::tlv::MIBString;
    using dog_torch::math::number::Integer64;
    auto total = static_cast<Mode>(*this).serialize();
    total.to_array()[0] = MIBString{ this->config().name };
    Value params = std::unordered_map<MIBString, Value>{};
    params.to_object()[MIBString{ "shift" }] = Value{ Integer64{this->shift_} };
    params.to_object()[MIBString{ "iv" }] = Value{ this->iv_.get_data() };
    total.to_array().push_back(params);
    return total;
}
bool NSROOT::CFB::set_uint64_param(const std::string& param, uint64_t value)
{
    if (param == "shift")
    {
        this->shift_ = value;
        return true;
    }
    return false;
}
bool NSROOT::CFB::set_string_param(const std::string& param, const std::string& value)
{
    return false;
}
bool NSROOT::CFB::set_binary_param(const std::string& param, const BinaryData& value)
{
    if (param == "iv")
    {
        this->iv_ = value;
        return true;
    }
    return false;
}
bool NSROOT::CFB::check(const algorithm::Algorithm& algorithm) const
{
    if (this->iv_.size() < algorithm.get_block_size() || this->shift_ > algorithm.get_block_size())
    {
        return false;
    }
    return true;
}

NSROOT::crypt_func NSROOT::CFB::get_mult_encrypt() const
{
    return [this](const BinaryData& p, const BinaryData& k, const algorithm::Algorithm& a)->BinaryData
        {
            return CFB::encrypt(p, k, a, this->padding_->get_padding(), this->iv_, this->shift_);
        };

}
NSROOT::crypt_func NSROOT::CFB::get_mult_decrypt() const
{
    return [this](const BinaryData& p, const BinaryData& k, const algorithm::Algorithm& a)->BinaryData
        {
            return CFB::decrypt(p, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_);
        };
}

NSROOT::stream_crypt_func NSROOT::CFB::get_stream_encrypt() const
{
    return [this](std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CFB::encrypt_stream(p, t, c, k, a, this->padding_->get_padding(), this->iv_, this->shift_);
        };
}
NSROOT::stream_crypt_func NSROOT::CFB::get_stream_decrypt() const
{
    return [this](std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CFB::decrypt_stream(p, t, c, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_);
        };
}

NSROOT::streamp_crypt_func NSROOT::CFB::get_streamp_encrypt() const
{
    return [this](PauseableChannel& pc, std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CFB::encryptp_stream(pc, p, t, c, k, a, this->padding_->get_padding(), this->iv_, this->shift_);
        };

}
NSROOT::streamp_crypt_func NSROOT::CFB::get_streamp_decrypt() const
{
    return [this](PauseableChannel& pc, std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CFB::decryptp_stream(pc, p, t, c, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_);
        };

}

#define CFB_INIT \
uint64_t block_size = algorithm.get_block_size(); \
uint64_t key_size = algorithm.get_key_size(); \
BinaryData iv_ = iv.sub_bytes_len(0,block_size);\
shift = shift == 0 ? block_size : shift;\
const BinaryData& key = available_key; \
using dog_torch::serialize::stream::read_bytes;\
using dog_torch::serialize::stream::read_bits;\
using dog_torch::serialize::stream::write_bits;

#define CFB_EN_INIT \
CFB_INIT \
algorithm::block_cryption_func block_encryption = algorithm.get_encrypt();\
algorithm::block_self_cryption_func block_self_encryption = algorithm.get_encrypt_self();


BinaryData NSROOT::CFB::encrypt(
    const BinaryData& plain, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func padding, const BinaryData& iv, uint64_t shift)
{
    CFB_EN_INIT;

    BinaryData crypt;
    crypt.reserve(plain.size());

    BinaryData buffer;
    uint64_t now = 0, num = 0;
    while (read_bytes(plain, plain.size(), now, buffer, shift, num) == shift)
    {
        block_self_encryption(iv_, block_size, key, key_size);
        buffer ^= iv_.sub_bytes_len(0, shift);
        crypt += buffer;
        std::move(iv_.begin() + shift, iv_.end(), iv_.begin());
        std::copy(buffer.begin(), buffer.end(), iv_.end() - shift);
    }
    block_self_encryption(iv_, block_size, key, key_size);
    padding(buffer, shift);
    buffer ^= iv_.sub_bytes_len(0, buffer.size());
    crypt += buffer;
    return crypt;

}
BinaryData NSROOT::CFB::decrypt(
    const BinaryData& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func unpadding, const BinaryData& iv, uint64_t shift)
{
    CFB_EN_INIT;

    BinaryData plain;
    plain.reserve(crypt.size());

    BinaryData buffer0,buffer1;
    uint64_t now = 0, num = 0;
    while (read_bytes(crypt, crypt.size(), now, buffer0, shift, num) == shift&& now < crypt.size())
    {
        buffer1 = buffer0;
        block_self_encryption(iv_, block_size, key, key_size);
        buffer0 ^= iv_.sub_bytes_len(0, shift);
        plain += buffer0;
        std::move(iv_.begin() + shift, iv_.end(), iv_.begin());
        std::copy(buffer1.begin(), buffer1.end(), iv_.end() - shift);
    }
    block_self_encryption(iv_, block_size, key, key_size);
    buffer0 ^= iv_.sub_bytes_len(0, shift);
    unpadding(buffer0, shift);
    plain += buffer0;
    return plain;
}

void NSROOT::CFB::encrypt_stream(
    std::istream& plain, uint64_t total, std::ostream& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func padding, const BinaryData& iv, uint64_t shift)
{
    CFB_EN_INIT;

    BinaryData buffer;
    uint64_t now = 0, num = 0;
    while (read_bytes(plain, total, now, buffer, shift, num) == shift)
    {
        block_self_encryption(iv_, block_size, key, key_size);
        buffer ^= iv_.sub_bytes_len(0, shift);
        crypt.write(buffer.data_stream(), shift);
        std::move(iv_.begin() + shift, iv_.end(), iv_.begin());
        std::copy(buffer.begin(), buffer.end(), iv_.end() - shift);
    }
    block_self_encryption(iv_, block_size, key, key_size);
    padding(buffer, shift);
    buffer ^= iv_.sub_bytes_len(0, buffer.size());
    crypt.write(buffer.data_stream(), buffer.size());
    crypt.flush();
}
void NSROOT::CFB::decrypt_stream(
    std::istream& crypt, uint64_t total, std::ostream& plain,
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func unpadding, const BinaryData& iv, uint64_t shift)
{
    CFB_EN_INIT;

    BinaryData buffer0, buffer1;
    uint64_t now = 0, num = 0;
    while (read_bytes(crypt, total, now, buffer0, shift, num) == shift&& now < total)
    {
        buffer1 = buffer0;
        block_self_encryption(iv_, block_size, key, key_size);
        buffer0 ^= iv_.sub_bytes_len(0, shift);
        plain.write(buffer0.data_stream(), shift);
        std::move(iv_.begin() + shift, iv_.end(), iv_.begin());
        std::copy(buffer1.begin(), buffer1.end(), iv_.end() - shift);
    }
    block_self_encryption(iv_, block_size, key, key_size);
    buffer0 ^= iv_.sub_bytes_len(0, num);
    unpadding(buffer0, shift);
    plain.write(buffer0.data_stream(), buffer0.size());
    plain.flush();
}

void NSROOT::CFB::encryptp_stream(
    PauseableChannel& pc, 
    std::istream& plain, uint64_t total, std::ostream& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func padding, const BinaryData& iv, uint64_t shift)
{
    CFB_EN_INIT;
    pc.start();
    BinaryData buffer;
    uint64_t now = 0, num = 0;
    while (read_bytes(plain, total, now, buffer, shift, num) == shift)
    {
        if (pc.check_status()) break; 
        block_self_encryption(iv_, block_size, key, key_size);
        buffer ^= iv_.sub_bytes_len(0, shift);
        crypt.write(buffer.data_stream(), shift);
        std::move(iv_.begin() + shift, iv_.end(), iv_.begin());
        std::copy(buffer.begin(), buffer.end(), iv_.end() - shift);
        pc.add_progress(shift * 1.0 / total);
    }
    block_self_encryption(iv_, block_size, key, key_size);
    padding(buffer, shift);
    buffer ^= iv_.sub_bytes_len(0, buffer.size());
    crypt.write(buffer.data_stream(), buffer.size());
    crypt.flush();
    pc.set_progress(1.0);
    pc.stop();
}
void NSROOT::CFB::decryptp_stream(
    PauseableChannel& pc, 
    std::istream& crypt, uint64_t total, std::ostream& plain, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func unpadding, const BinaryData& iv, uint64_t shift)
{
    CFB_EN_INIT;
    pc.start();
    BinaryData buffer0, buffer1;
    uint64_t now = 0, num = 0;
    while (read_bytes(crypt, total, now, buffer0, shift, num) == shift&& now < total)
    {
        if (pc.check_status()) break;
        buffer1 = buffer0;
        block_self_encryption(iv_, block_size, key, key_size);
        buffer0 ^= iv_.sub_bytes_len(0, shift);
        plain.write(buffer0.data_stream(), shift);
        std::move(iv_.begin() + shift, iv_.end(), iv_.begin());
        std::copy(buffer1.begin(), buffer1.end(), iv_.end() - shift);
        pc.add_progress(shift * 1.0 / total);
    }
    block_self_encryption(iv_, block_size, key, key_size);
    buffer0 ^= iv_.sub_bytes_len(0, num);
    unpadding(buffer0, shift);
    plain.write(buffer0.data_stream(), buffer0.size());
    plain.flush();
    pc.set_progress(1.0);
    pc.stop();
}

NSROOT::CFBb::CFBb(const BinaryData& iv, uint64_t shift, const padding::Padding& padding)
    : Mode(padding), iv_(iv), shift_(shift)
{}
NSROOT::CFBb::CFBb(const BinaryData& iv, const padding::Padding& padding)
    : Mode(padding), iv_(iv), shift_(0)
{}
NSROOT::CFBb::CFBb(const CFBb& other) : Mode(other)
{
    this->iv_ = other.iv_;
    this->shift_ = other.shift_;
}
NSROOT::CFBb& NSROOT::CFBb::operator=(const CFBb& other)
{
    Mode::operator=(other);
    this->iv_ = other.iv_;
    this->shift_ = other.shift_;
    return *this;
}
NSROOT::CFBb::CFBb(CFBb&& other) noexcept : Mode(std::move(other))
{
    this->iv_ = std::move(other.iv_);
    this->shift_ = std::move(other.shift_);
}
NSROOT::CFBb& NSROOT::CFBb::operator=(CFBb&& other) noexcept
{
    if (this ==&other) return *this;
    Mode::operator=(std::move(other));
    this->iv_ = std::move(other.iv_);
    this->shift_ = std::move(other.shift_);
    return *this;
}

std::unique_ptr<NSROOT::Mode> NSROOT::CFBb::clone() const
{
    return std::make_unique<CFBb>(*this);
}
const NSROOT::Config& NSROOT::CFBb::params_config()
{
    static const Config config = Config("CFBb", {
        {"iv",ParamType::Binary},
        {"shift",ParamType::UInt64}
        });
    return config;
}
NSROOT::Config NSROOT::CFBb::config() const
{
    return params_config();
}
std::string NSROOT::CFBb::fmt_string() const
{
    if (this->shift_ == 0)
    {
        if (this->padding_->fmt_string() != "NoPadding")
        {
            return std::format("CFB<{}>", this->padding_->fmt_string());
        }
        else
        {
            return "CFB";
        }
    }
    else
    {
        if (this->padding_->fmt_string() != "NoPadding")
        {
            return std::format("CFB<{}b,{}>", this->shift_, this->padding_->fmt_string());
        }
        else
        {
            return std::format("CFB<{}b>", this->shift_);
        }
    }
}
Value NSROOT::CFBb::serialize() const
{
    using dog_torch::serialize::tlv::MIBString;
    using dog_torch::math::number::Integer64;
    Value total = std::vector<Value>{};;
    total.to_array()[0] = MIBString{ this->config().name };
    total.to_array().push_back(MIBString{ this->config().name });
    Value params = std::unordered_map<MIBString, Value>{};
    params.to_object()[MIBString{ "shift" }] = Value{ Integer64{this->shift_} };
    params.to_object()[MIBString{ "iv" }] = Value{ this->iv_.get_data() };
    total.to_array().push_back(params);
    return total;
}
bool NSROOT::CFBb::set_uint64_param(const std::string& param, uint64_t value)
{
    if (param == "shift")
    {
        this->shift_ = value;
        return true;
    }
    return false;
}
bool NSROOT::CFBb::set_string_param(const std::string& param, const std::string& value)
{
    return false;
}
bool NSROOT::CFBb::set_binary_param(const std::string& param, const BinaryData& value)
{
    if (param == "iv")
    {
        this->iv_ = value;
        return true;
    }
    return false;
}
bool NSROOT::CFBb::check(const algorithm::Algorithm& algorithm) const
{
    if (this->iv_.size() < algorithm.get_block_size())
    {
        return false;
    }
    return true;
}

NSROOT::crypt_func NSROOT::CFBb::get_mult_encrypt() const
{
    if (this->shift_ % 8 == 0)
    {
        return [this](const BinaryData& p, const BinaryData& k, const algorithm::Algorithm& a)->BinaryData
            {
                return CFB::encrypt(p, k, a, this->padding_->get_padding(), this->iv_, this->shift_ / 8);
            };
    }
    return [this](const BinaryData& p, const BinaryData& k, const algorithm::Algorithm& a)->BinaryData
        {
            return CFBb::encrypt(p, k, a, this->iv_, this->shift_);
        };
}
NSROOT::crypt_func NSROOT::CFBb::get_mult_decrypt() const
{
    if (this->shift_ % 8 == 0) 
    {
        return [this](const BinaryData& p, const BinaryData& k, const algorithm::Algorithm& a)->BinaryData
            {
                return CFB::decrypt(p, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_ / 8);
            };
    }
    return [this](const BinaryData& p, const BinaryData& k, const algorithm::Algorithm& a)->BinaryData
        {
            return CFBb::decrypt(p, k, a, this->iv_, this->shift_);
        };
}

NSROOT::stream_crypt_func NSROOT::CFBb::get_stream_encrypt() const
{
    if (this->shift_ % 8 == 0) 
    {
        return [this](std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
            {
                return CFB::encrypt_stream(p, t, c, k, a, this->padding_->get_padding(), this->iv_, this->shift_ / 8);
            };
    }
    return [this](std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CFBb::encrypt_stream(p, t, c, k, a, this->iv_, this->shift_);
        };
}
NSROOT::stream_crypt_func NSROOT::CFBb::get_stream_decrypt() const
{
    if (this->shift_ % 8 == 0) 
    {
        return [this](std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
            {
                return CFB::decrypt_stream(p, t, c, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_ / 8);
            };
    }
    return [this](std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CFBb::decrypt_stream(p, t, c, k, a, this->iv_, this->shift_);
        };
}

NSROOT::streamp_crypt_func NSROOT::CFBb::get_streamp_encrypt() const
{
    if (this->shift_ % 8 == 0)
    {
        return [this](PauseableChannel& pc, std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
            {
                return CFB::encryptp_stream(pc, p, t, c, k, a, this->padding_->get_padding(), this->iv_, this->shift_ / 8);
            };
    }
    return [this](PauseableChannel& pc, std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CFBb::encryptp_stream(pc, p, t, c, k, a, this->iv_, this->shift_);
        };
}
NSROOT::streamp_crypt_func NSROOT::CFBb::get_streamp_decrypt() const
{
    if (this->shift_ % 8 == 0)
    {
        return [this](PauseableChannel& pc, std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
            {
                return CFB::decryptp_stream(pc, p, t, c, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_ / 8);
            };
    }
    return [this](PauseableChannel& pc, std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return CFBb::decryptp_stream(pc, p, t, c, k, a, this->iv_, this->shift_);
        };
}

BinaryData NSROOT::CFBb::encrypt(
    const BinaryData& plain, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift)
{
    CFB_EN_INIT;
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
        iv_.bit_move_self(false, false, shift);
        iv_.resize(block_size);
        buffer.bit_move_self(true, false, (block_size * 8 - shift));
        iv_ ^= buffer;
    }
    block_self_encryption(iv_, block_size, key, key_size);
    buffer ^= iv_;
    write_bits(crypt, output_byte_buffer, write_next_bit, shift, buffer, num);
    return crypt;
}
BinaryData NSROOT::CFBb::decrypt(
    const BinaryData& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift)
{
    CFB_EN_INIT;
    BinaryData plain;
    plain.reserve(crypt.size());

    BinaryData buffer0, buffer1;
    uint64_t now = 0, num = 0;
    uint8_t read_now_bit = 0, output_byte_buffer = 0, write_next_bit = 0;
    while (read_bits(crypt, crypt.size(), now, read_now_bit, buffer0, shift, num) == shift)
    {
        buffer1 = buffer0;
        block_self_encryption(iv_, block_size, key, key_size);
        buffer0 ^= iv_;
        write_bits(plain, output_byte_buffer, write_next_bit, shift, buffer0, num);
        iv_.bit_move_self(false, false, shift);
        iv_.resize(block_size);
        buffer1 >>= (block_size * 8 - shift);
        iv_ ^= buffer1;
    }
    block_self_encryption(iv_, block_size, key, key_size);
    buffer0 ^= iv_;
    write_bits(plain, output_byte_buffer, write_next_bit, shift, buffer0, num);
    return plain;
}

void NSROOT::CFBb::encrypt_stream(
    std::istream& plain, uint64_t total, std::ostream& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift)
{
    CFB_EN_INIT;
    BinaryData buffer;
    uint64_t now = 0, num = 0;
    uint8_t read_now_bit = 0, output_byte_buffer = 0, write_next_bit = 0;
    while (read_bits(plain, total, now, read_now_bit, buffer, shift, num) == shift)
    {
        block_self_encryption(iv_, block_size, key, key_size);
        buffer ^= iv_;
        write_bits(crypt, output_byte_buffer, write_next_bit, shift, buffer, num);
        iv_.bit_move_self(false, false, shift);
        iv_.resize(block_size);
        buffer.bit_move_self(true, false, (block_size * 8 - shift));
        iv_ ^= buffer;
    }
    block_self_encryption(iv_, block_size, key, key_size);
    buffer ^= iv_;
    write_bits(crypt, output_byte_buffer, write_next_bit, shift, buffer, num);
    crypt.flush();
}
void NSROOT::CFBb::decrypt_stream(
    std::istream& crypt, uint64_t total, std::ostream& plain,
    const BinaryData& available_key,
    const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift)
{
    CFB_EN_INIT;
    BinaryData buffer0, buffer1;
    uint64_t now = 0, num = 0;
    uint8_t read_now_bit = 0, output_byte_buffer = 0, write_next_bit = 0;
    while (read_bits(crypt, total, now, read_now_bit, buffer0, shift, num) == shift)
    {
        buffer1 = buffer0;
        block_self_encryption(iv_, block_size, key, key_size);
        buffer0 ^= iv_;
        write_bits(plain, output_byte_buffer, write_next_bit, shift, buffer0, num);
        iv_.bit_move_self(false, false, shift);
        iv_.resize(block_size);
        buffer1 >>= (block_size * 8 - shift);
        iv_ ^= buffer1;
    }
    block_self_encryption(iv_, block_size, key, key_size);
    buffer0 ^= iv_;
    write_bits(plain, output_byte_buffer, write_next_bit, shift, buffer0, num);
    plain.flush();
}

void NSROOT::CFBb::encryptp_stream(
    PauseableChannel& pc, 
    std::istream& plain, uint64_t total, std::ostream& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift)
{
    CFB_EN_INIT;
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
        iv_.bit_move_self(false, false, shift);
        iv_.resize(block_size);
        buffer.bit_move_self(true, false, (block_size * 8 - shift));
        iv_ ^= buffer;
        pc.add_progress(num * 1.0 / (total * 8));
    }
    block_self_encryption(iv_, block_size, key, key_size);
    buffer ^= iv_;
    write_bits(crypt, output_byte_buffer, write_next_bit, shift, buffer, num);
    crypt.flush();
    pc.set_progress(1.0);
    pc.stop();
}
void NSROOT::CFBb::decryptp_stream(
    PauseableChannel& pc, 
    std::istream& crypt, uint64_t total, std::ostream& plain, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift)
{
    CFB_EN_INIT;
    pc.start();
    BinaryData buffer0, buffer1;
    uint64_t now = 0, num = 0;
    uint8_t read_now_bit = 0, output_byte_buffer = 0, write_next_bit = 0;
    while (read_bits(crypt, total, now, read_now_bit, buffer0, shift, num) == shift)
    {
        if (pc.check_status()) break;
        buffer1 = buffer0;
        block_self_encryption(iv_, block_size, key, key_size);
        buffer0 ^= iv_;
        write_bits(plain, output_byte_buffer, write_next_bit, shift, buffer0, num);
        iv_.bit_move_self(false, false, shift);
        iv_.resize(block_size);
        buffer1 >>= (block_size * 8 - shift);
        iv_ ^= buffer1;
        pc.add_progress(num * 1.0 / (total * 8));
    }
    block_self_encryption(iv_, block_size, key, key_size);
    buffer0 ^= iv_;
    write_bits(plain, output_byte_buffer, write_next_bit, shift, buffer0, num);
    plain.flush();
    pc.set_progress(1.0);
    pc.stop();
}
