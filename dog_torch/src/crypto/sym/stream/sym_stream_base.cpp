#include "crypto/sym/stream/sym_stream_base.h"

namespace NSROOT = dog_torch::crypto::sym::stream;
using BinaryData = dog_torch::serialize::BinaryData;

using dog_torch::utils::from_c_str;
using dog_torch::utils::from_uint64;
using dog_torch::utils::array_to_view;

constexpr auto ERROR_SHIFT_TOO_LARGE = from_c_str("shift is too large than algorithm updata size");

NSROOT::algorithm::Config::Config(const std::string& name, const std::string& effective_region, const std::string& key_size_region)
	: name(name), effective_region(effective_region), key_size_region(key_size_region) {}

NSROOT::algorithm::Algorithm::Algorithm(uint64_t effective, uint64_t key_size) : effective_(effective), key_size_(key_size) {}

NSROOT::algorithm::Algorithm::Algorithm(const Algorithm& other) = default;
NSROOT::algorithm::Algorithm& NSROOT::algorithm::Algorithm::operator=(const Algorithm& other) = default;
NSROOT::algorithm::Algorithm::Algorithm(Algorithm&& other) noexcept = default;
NSROOT::algorithm::Algorithm& NSROOT::algorithm::Algorithm::operator=(Algorithm&& other) noexcept = default;

NSROOT::algorithm::Algorithm::~Algorithm() = default;

NSROOT::algorithm::Config NSROOT::algorithm::Algorithm::config() const
{
	return Config("", "", "");
}
void NSROOT::algorithm::Algorithm::init()
{

}
std::unique_ptr<NSROOT::algorithm::Algorithm> NSROOT::algorithm::Algorithm::clone() const
{
    return std::make_unique<Algorithm>(*this);
}
uint64_t NSROOT::algorithm::Algorithm::updata_size() const
{
    return 0;
}
NSROOT::algorithm::UpdateFunc NSROOT::algorithm::Algorithm::update_func()
{
	return UpdateFunc();
}

NSROOT::algorithm::CombineFunc NSROOT::algorithm::Algorithm::combine_func()
{
    return XOR_combine;
}

void NSROOT::algorithm::Algorithm::XOR_combine(BinaryData& dst, const BinaryData& src)
{
    dst ^= src;
}


NSROOT::StreamCipher::StreamCipher(const BinaryData& key, const algorithm::Algorithm& alg, uint64_t shift, bool is_bit)
	: Cipher(key), alg_(alg.clone()), shift_(shift), is_bit_(is_bit)
{}

void NSROOT::StreamCipher::init()
{
    if (
        (!this->is_bit_&& this->alg_->updata_size() < this->shift_) ||
        (this->is_bit_&& this->alg_->updata_size() * 8 < this->shift_)
        )
    {
        throw DOG_EXCEPTION(array_to_view(ERROR_SHIFT_TOO_LARGE));
    }
    this->alg_->init();
}
bool NSROOT::StreamCipher::effective() const
{
    if (
        (!this->is_bit_&& this->alg_->updata_size() < this->shift_) ||
        (this->is_bit_&& this->alg_->updata_size() * 8 < this->shift_)
        )
    {
        return false;
    }
    return true;
}

BinaryData NSROOT::StreamCipher::encrypt(const BinaryData& plain)
{
    using dog_torch::serialize::stream::read_bytes;
    using dog_torch::serialize::stream::read_bits;
    using dog_torch::serialize::stream::write_bits;

    bool is_bit = this->shift_ == 0 ? false : this->is_bit_;
    uint64_t shift = this->shift_ == 0 ? this->alg_->updata_size() : this->shift_;
    auto up_func = this->alg_->update_func();
    auto cm_func = this->alg_->combine_func();

    BinaryData crypt;
    crypt.reserve(plain.size());

    if (!is_bit)
    {
        BinaryData buffer0, buffer1;
        uint64_t now = 0, num = 0;
        while (read_bytes(plain, plain.size(), now, buffer0, shift, num) == shift)
        {
            buffer1 = up_func(this->ori_key_);
            cm_func(buffer0, buffer1);
            crypt += buffer0;
        }
        buffer1 = up_func(this->ori_key_);
        cm_func(buffer0, buffer1);
        crypt += buffer0.sub_bytes_len(0, num);
    }
    else
    {
        BinaryData buffer0, buffer1;
        uint64_t now = 0, num = 0;
        uint8_t read_now_bit = 0, write_byte_buffer = 0, write_now_bit = 0;
        while (read_bits(plain, plain.size(), now, read_now_bit, buffer0, shift, num) == shift)
        {
            buffer1 = up_func(this->ori_key_);
            cm_func(buffer0, buffer1);
            write_bits(crypt, write_byte_buffer, write_now_bit, shift, buffer0, shift);
        }
        buffer1 = up_func(this->ori_key_);
        cm_func(buffer0, buffer1);
        write_bits(crypt, write_byte_buffer, write_now_bit, shift, buffer0, num);
    }
    alg_->init();
    return crypt;
}
BinaryData NSROOT::StreamCipher::decrypt(const BinaryData& crypt)
{
	return encrypt(crypt);
}

void NSROOT::StreamCipher::encrypt_stream(std::istream& plain, uint64_t total, std::ostream& crypt)
{
    using dog_torch::serialize::stream::read_bytes;
    using dog_torch::serialize::stream::read_bits;
    using dog_torch::serialize::stream::write_bits;

    bool is_bit = this->shift_ == 0 ? false : this->is_bit_;
    uint64_t shift = this->shift_ == 0 ? this->alg_->updata_size() : this->shift_;
    auto up_func = this->alg_->update_func();
    auto cm_func = this->alg_->combine_func();

    if (!is_bit)
    {
        BinaryData buffer0, buffer1;
        uint64_t now = 0, num = 0;
        while (read_bytes(plain, total, now, buffer0, shift, num) == shift)
        {
            buffer1 = up_func(this->ori_key_);
            cm_func(buffer0, buffer1);
            crypt.write(buffer0.data_stream(), shift);
        }
        buffer1 = up_func(this->ori_key_);
        cm_func(buffer0, buffer1);
        crypt.write(buffer0.data_stream(), num);
    }
    else
    {
        BinaryData buffer0, buffer1;
        uint64_t now = 0, num = 0;
        uint8_t read_now_bit = 0, write_byte_buffer = 0, write_now_bit = 0;
        while (read_bits(plain, total, now, read_now_bit, buffer0, shift, num) == shift)
        {
            buffer1 = up_func(this->ori_key_);
            cm_func(buffer0, buffer1);
            write_bits(crypt, write_byte_buffer, write_now_bit, shift, buffer0, shift);
        }
        buffer1 = up_func(this->ori_key_);
        cm_func(buffer0, buffer1);
        write_bits(crypt, write_byte_buffer, write_now_bit, shift, buffer0, num);
    }
    alg_->init();
    crypt.flush();
}
void NSROOT::StreamCipher::decrypt_stream(std::istream& crypt, uint64_t total, std::ostream& plain)
{
    encrypt_stream(crypt, total, plain);
}

void NSROOT::StreamCipher::encryptp_stream(PauseableChannel& pc, std::istream& plain, uint64_t total, std::ostream& crypt)
{
    using dog_torch::serialize::stream::read_bytes;
    using dog_torch::serialize::stream::read_bits;
    using dog_torch::serialize::stream::write_bits;
    pc.start();
    bool is_bit = this->shift_ == 0 ? false : this->is_bit_;
    uint64_t shift = this->shift_ == 0 ? this->alg_->updata_size() : this->shift_;
    auto up_func = this->alg_->update_func();
    auto cm_func = this->alg_->combine_func();

    if (!is_bit)
    {
        BinaryData buffer0, buffer1;
        uint64_t now = 0, num = 0;
        while (read_bytes(plain, total, now, buffer0, shift, num) == shift)
        {
            if (pc.check_status()) break;
            buffer1 = up_func(this->ori_key_);
            cm_func(buffer0, buffer1);
            crypt.write(buffer0.data_stream(), shift);
            pc.add_progress(shift * 1.0 / total);
        }
        buffer1 = up_func(this->ori_key_);
        cm_func(buffer0, buffer1);
        crypt.write(buffer0.data_stream(), num);
    }
    else
    {
        BinaryData buffer0, buffer1;
        uint64_t now = 0, num = 0;
        uint8_t read_now_bit = 0, write_byte_buffer = 0, write_now_bit = 0;
        while (read_bits(plain, total, now, read_now_bit, buffer0, shift, num) == shift)
        {
            if (pc.check_status()) break;
            buffer1 = up_func(this->ori_key_);
            cm_func(buffer0, buffer1);
            write_bits(crypt, write_byte_buffer, write_now_bit, shift, buffer0, shift);
            pc.add_progress(shift * 1.0 / (total * 8));
        }
        buffer1 = up_func(this->ori_key_);
        cm_func(buffer0, buffer1);
        write_bits(crypt, write_byte_buffer, write_now_bit, shift, buffer0, num);
    }
    crypt.flush();
    alg_->init();
    pc.set_progress(1.0);
    pc.stop();
}
void NSROOT::StreamCipher::decryptp_stream(PauseableChannel& pc, std::istream& crypt, uint64_t total, std::ostream& plain)
{
    encryptp_stream(pc, crypt, total, plain);
}