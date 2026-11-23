#include "crypto/sym/block/modes/ECB.h"
#include "error_msg.h"

namespace NSROOT = dog_torch::crypto::sym::block::mode;
using dog_torch::serialize::BinaryData;
using Value = dog_torch::serialize::tlv::Value;

NSROOT::ECB::ECB(const padding::Padding& padding) : Mode(padding.clone()) {};

NSROOT::ECB::ECB(const ECB& other) : Mode(other) {};
NSROOT::ECB& NSROOT::ECB::operator=(const ECB& other)
{
    Mode::operator=(other);
    return *this;
}
NSROOT::ECB::ECB(ECB&& other) noexcept
{
    Mode::operator=(std::move(other));
}
NSROOT::ECB& NSROOT::ECB::operator=(ECB&& other) noexcept
{
    if (this ==&other)return *this;
    Mode::operator=(std::move(other));
    return *this;
}

std::unique_ptr<NSROOT::Mode> NSROOT::ECB::clone() const
{
    return std::make_unique<ECB>(*this);
}
const NSROOT::Config& NSROOT::ECB::params_config()
{
    static const Config config = Config("ECB", {});
    return config;
}
NSROOT::Config NSROOT::ECB::config() const
{
    return params_config();
}
Value NSROOT::ECB::serialize() const
{
    using dog_torch::serialize::tlv::MIBString;
    auto total = reinterpret_cast<const Mode*>(this)->serialize();
    total.to_array()[0] = MIBString{ this->config().name };
    return total;
}
std::string NSROOT::ECB::fmt_string() const
{
    return std::format("ECB<{}>", this->padding_->fmt_string());
}
bool NSROOT::ECB::set_uint64_param(const std::string& param, uint64_t value)
{
    return false;
}
bool NSROOT::ECB::set_string_param(const std::string& param, const std::string& value)
{
    return false;
}
bool NSROOT::ECB::set_binary_param(const std::string& param, const BinaryData& value)
{
    return false;
}
bool NSROOT::ECB::check(const algorithm::Algorithm& algorithm) const
{
    return true;
}

NSROOT::crypt_func NSROOT::ECB::get_mult_encrypt() const
{
    return [this](const BinaryData& p, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
        {
            return ECB::encrypt(p, k, a, this->padding_->get_padding());
        };
}
NSROOT::crypt_func NSROOT::ECB::get_mult_decrypt() const
{
    return [this](const BinaryData& c, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
        {
            return ECB::decrypt(c, k, a, this->padding_->get_unpadding());
        };
}

NSROOT::stream_crypt_func NSROOT::ECB::get_stream_encrypt() const
{
    return [this](std::function<uint8_t(uint64_t, uint64_t)> onRunning, std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return ECB::encrypt_stream(p, t, c, k, a, this->padding_->get_padding(), onRunning);
        };
}
NSROOT::stream_crypt_func NSROOT::ECB::get_stream_decrypt() const
{
    return [this](std::function<uint8_t(uint64_t, uint64_t)> onRunning, std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
        {
            return ECB::decrypt_stream(c, t, p, k, a, this->padding_->get_unpadding(), onRunning);
        };
}


#define ECB_INIT \
uint64_t block_size = algorithm.get_block_size(); \
uint64_t key_size = algorithm.get_key_size(); \
const BinaryData& key = available_key; \
using dog_torch::serialize::stream::read_bytes;

#define ECB_EN_INIT \
ECB_INIT \
algorithm::block_cryption_func block_encryption = algorithm.get_encrypt();\
algorithm::block_self_cryption_func block_self_encryption = algorithm.get_encrypt_self();

#define ECB_DE_INIT \
ECB_INIT \
algorithm::block_cryption_func block_decryption = algorithm.get_decrypt();\
algorithm::block_self_cryption_func block_self_decryption = algorithm.get_decrypt_self();

BinaryData NSROOT::ECB::encrypt(
    const BinaryData& plain, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func padding)
{
    ECB_EN_INIT;

    BinaryData buffer;
    padding(buffer, block_size);
    if (plain.size() % block_size != 0 && buffer.size() < block_size) 
        throw DOG_EXCEPTION(array_to_view(ERROR_ECB_ALLOW_SIZE_OR_PADDING));

    BinaryData crypt;
    crypt.reserve(((1 + (plain.size() - 1) / block_size) * block_size));

    uint64_t now = 0;
    uint64_t buffer_size = 0;
    while (read_bytes(plain.get_data(), plain.size(), now, buffer.get_data(), block_size, buffer_size) == block_size)
    {
        crypt += block_encryption(buffer, block_size, key, key_size);
    }
    padding(buffer, block_size);
    if (buffer.size() != 0)
    {
        if (buffer.size() < block_size) throw DOG_EXCEPTION(array_to_view(ERROR_ECB_ALLOW_SIZE_OR_PADDING));
        crypt += block_encryption(buffer, block_size, key, key_size);
    }
    return crypt;

}
BinaryData NSROOT::ECB::decrypt(
    const BinaryData& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func unpadding)
{
    ECB_DE_INIT;
    
    if (crypt.size() % block_size != 0) 
        throw DOG_EXCEPTION(array_to_view(ERROR_ECB_CRYPT_ALLOW_SIZE));
    BinaryData plain;
    plain.reserve(crypt.size());
    
    BinaryData buffer;
    uint64_t now = 0;
    uint64_t buffer_size = 0;
    while (read_bytes(crypt.get_data(), crypt.size(), now, buffer.get_data(), block_size, buffer_size) == block_size && now < crypt.size())
    {
        plain += block_decryption(buffer, block_size, key, key_size);
    }
    if (buffer.size() != 0)
    {
        if (buffer.size() < block_size) throw DOG_EXCEPTION(array_to_view(ERROR_ECB_CRYPT_ALLOW_SIZE));
        block_self_decryption(buffer, block_size, key, key_size);
    }
    unpadding(buffer, block_size);
    plain += buffer;
    return plain;
}

void NSROOT::ECB::encrypt_stream(
    std::istream& plain, uint64_t total, std::ostream& crypt, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func padding,
    std::function<uint8_t(uint64_t, uint64_t)> onRunning)
{
    ECB_EN_INIT;

    BinaryData buffer;
    padding(buffer, block_size);
    if (total % block_size != 0 && buffer.size() < block_size) 
        throw DOG_EXCEPTION(array_to_view(ERROR_ECB_ALLOW_SIZE_OR_PADDING));

    uint64_t now = 0;
    uint64_t buffer_size = 0;
    while (read_bytes(plain, total, now, buffer.get_data(), block_size, buffer_size) == block_size)
    {
        if (onRunning(block_size, total) > 0x80) return;
        block_self_encryption(buffer, block_size, key, key_size);
        crypt.write(buffer.data_stream(), block_size);
    }
    padding(buffer, block_size);
    if (buffer.size() != 0)
    {
        if (buffer.size() < block_size) throw DOG_EXCEPTION(array_to_view(ERROR_ECB_ALLOW_SIZE_OR_PADDING));
        block_self_encryption(buffer, block_size, key, key_size);
        crypt.write(buffer.data_stream(), block_size);
    }
    crypt.flush();
}
void NSROOT::ECB::decrypt_stream(
    std::istream& crypt, uint64_t total, std::ostream& plain, 
    const BinaryData& available_key, 
    const algorithm::Algorithm& algorithm, padding::padding_func unpadding,
    std::function<uint8_t(uint64_t, uint64_t)> onRunning)
{
    ECB_DE_INIT;
    if (total % block_size != 0) 
        throw DOG_EXCEPTION(array_to_view(ERROR_ECB_CRYPT_ALLOW_SIZE));
    BinaryData buffer;
    uint64_t now = 0;
    uint64_t buffer_size = 0;
    while (read_bytes(crypt, total, now, buffer.get_data(), block_size, buffer_size) == block_size&& now < total)
    {
        if (onRunning(block_size, total) > 0x80) return;
        block_self_decryption(buffer, block_size, key, key_size);
        plain.write(buffer.data_stream(), block_size);
    }
    if (buffer.size() != 0)
    {
        if (buffer.size() < block_size) throw DOG_EXCEPTION(array_to_view(ERROR_ECB_CRYPT_ALLOW_SIZE));
        block_self_decryption(buffer, block_size, key, key_size);
    }
    unpadding(buffer, block_size);
    plain.write(buffer.data_stream(), buffer.size());
    plain.flush();
}

#undef ECB_INIT
#undef ECB_EN_INIT
#undef ECB_DE_INIT
