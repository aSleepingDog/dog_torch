#include "crypto/asym/paddings/OAEP.h"
#include "error_msg.h"

namespace NSROOT = dog_torch::crypto::asym::padding;
using dog_torch::serialize::BinaryData;
using KeyPair = dog_torch::crypto::asym::KeyPair;

BinaryData NSROOT::OAEP::MGF1(const BinaryData& data, uint64_t output, const NSROOT::OAEP::HashAlg& alg)
{
    //alg.get_out_size()
    BinaryData T;
    dog_torch::crypto::hash::Generator gen(alg);
    gen.init();
    for (uint32_t i = 0; i * alg.get_out_size() < output; i++)
    {
        BinaryData num(4);
        num[0] = i >> 24;
        num[1] = i >> 16;
        num[2] = i >> 8;
        num[3] = i;
        T += gen.calculate(data + num);
    }
    return T.sub_bytes_len(0, output);
}
BinaryData NSROOT::OAEP::padding(const BinaryData& plain, uint64_t key_size, const BinaryData& label, const NSROOT::OAEP::HashAlg& alg)
{
    key_size /= 8;
    uint64_t hlen = alg.get_out_size();
    uint64_t mlen = plain.size();
    if (mlen > key_size - 2 * hlen - 2)
    {
        throw DOG_EXCEPTION(array_to_view(ERROR_OAEP_TO_LARGE));
    }
    BinaryData ps;
    ps.resize(key_size - mlen - 2 * hlen - 2);
    dog_torch::crypto::hash::Generator gen(alg);
    gen.init();
    BinaryData DB = label;
    DB = gen.calculate(DB) + ps;
    DB.push_back(0x01);
    DB += plain;
    //std::cout << "DB:" << DB.to_hex_string(true) << std::endl;
    BinaryData seed;
    //std::random_device rd;
    //while (seed.size() < hlen)
    //{
    //    seed.push_back(rd());
    //}
    seed.resize(hlen, 0);
    dog_torch::math::random::random_block(seed.data_stream(), hlen);
    //std::cout << "seed:" << seed.to_hex_string(true) << std::endl;
    BinaryData maskedDB = MGF1(seed, key_size - hlen - 1, alg) ^ DB;
    //std::cout << "maskedDB:" << maskedDB.to_hex_string(true) << std::endl;
    BinaryData maskedSeed = MGF1(maskedDB, hlen, alg) ^ seed;
    //std::cout << "maskedSeed:" << maskedSeed.to_hex_string(true) << std::endl;
    BinaryData plain_;
    plain_.push_back(0x00);
    plain_ += maskedSeed;
    plain_ += maskedDB;
    return plain_;
}
BinaryData NSROOT::OAEP::padding(const BinaryData& plain, uint64_t key_size, const BinaryData& label, const HashAlg& t_alg, const HashAlg& m_alg)
{
    key_size /= 8;
    uint64_t hlen = t_alg.get_out_size();
    uint64_t mlen = plain.size();
    if (mlen > key_size - 2 * hlen - 2)
    {
        throw DOG_EXCEPTION(array_to_view(ERROR_OAEP_TO_LARGE));
    }
    BinaryData ps;
    ps.resize(key_size - mlen - 2 * hlen - 2);
    dog_torch::crypto::hash::Generator gen(t_alg);
    gen.init();
    BinaryData DB = label;
    DB = gen.calculate(DB) + ps;
    DB.push_back(0x01);
    DB += plain;
    //std::cout << "DB:" << DB.to_hex_string(true) << std::endl;
    BinaryData seed;
    std::random_device rd;
    while (seed.size() < hlen)
    {
        seed.push_back(rd());
    }
    //std::cout << "seed:" << seed.to_hex_string(true) << std::endl;
    BinaryData maskedDB = MGF1(seed, key_size - hlen - 1, m_alg) ^ DB;
    //std::cout << "maskedDB:" << maskedDB.to_hex_string(true) << std::endl;
    BinaryData maskedSeed = MGF1(maskedDB, hlen, m_alg) ^ seed;
    //std::cout << "maskedSeed:" << maskedSeed.to_hex_string(true) << std::endl;
    BinaryData plain_;
    plain_.push_back(0x00);
    plain_ += maskedSeed;
    plain_ += maskedDB;
    return plain_;
}
BinaryData NSROOT::OAEP::unpadding(const BinaryData& crypt, uint64_t key_size, const BinaryData& label, const NSROOT::OAEP::HashAlg& alg)
{
    key_size /= 8;
    constexpr uint64_t START = 0;
    uint64_t hlen = alg.get_out_size();
    BinaryData maskedSeed = crypt.sub_bytes_len(START, hlen);
    //std::cout << "maskedSeed:" << maskedSeed.to_hex_string(true) << std::endl;
    BinaryData maskedDB = crypt.sub_bytes_len(START + hlen, key_size - hlen);
    //std::cout << "maskedDB:" << maskedDB.to_hex_string(true) << std::endl;
    BinaryData seed = MGF1(maskedDB, hlen, alg) ^ maskedSeed;
    seed = seed.sub_bytes_len(0, hlen);
    //std::cout << "seed:" << seed.to_hex_string(true) << std::endl;
    BinaryData DB = MGF1(seed, key_size - hlen - 1, alg) ^ maskedDB;
    auto start = std::find(DB.cbegin() + hlen, DB.cend(), 0x01);
    if (start == DB.cend())
    {
        //wrong in format
        throw DOG_EXCEPTION(array_to_view(ERROR_OAEP_INVALID));
    }
    //std::cout << "DB:" << DB.to_hex_string(true) << std::endl;
    dog_torch::crypto::hash::Generator gen(alg);
    gen.init();
    BinaryData LHash = gen.calculate(label);
    if (DB.sub_bytes_pos(0, hlen) != LHash)
    {
        //wrong in label
        throw DOG_EXCEPTION(array_to_view(ERROR_OAEP_INVALID));
    }
    return DB.sub_bytes_pos(start + 1, DB.cend());
}
BinaryData NSROOT::OAEP::unpadding(const BinaryData& crypt, uint64_t key_size, const BinaryData& label, const HashAlg& t_alg, const HashAlg& m_alg)
{
    key_size /= 8;
    constexpr uint64_t START = 0;
    uint64_t hlen = t_alg.get_out_size();
    BinaryData maskedSeed = crypt.sub_bytes_len(START, hlen);
    //std::cout << "maskedSeed:" << maskedSeed.to_hex_string(true) << std::endl;
    BinaryData maskedDB = crypt.sub_bytes_len(START + hlen, key_size - hlen);
    //std::cout << "maskedDB:" << maskedDB.to_hex_string(true) << std::endl;
    BinaryData seed = MGF1(maskedDB, hlen, m_alg) ^ maskedSeed;
    seed = seed.sub_bytes_len(0, hlen);
    //std::cout << "seed:" << seed.to_hex_string(true) << std::endl;
    BinaryData DB = MGF1(seed, key_size - hlen - 1, m_alg) ^ maskedDB;
    auto start = std::find(DB.cbegin() + hlen, DB.cend(), 0x01);
    if (start == DB.cend())
    {
        //wrong in format
        throw DOG_EXCEPTION(array_to_view(ERROR_OAEP_INVALID));
    }
    //std::cout << "DB:" << DB.to_hex_string(true) << std::endl;
    dog_torch::crypto::hash::Generator gen(t_alg);
    gen.init();
    BinaryData LHash = gen.calculate(label);
    if (DB.sub_bytes_pos(0, hlen) != LHash)
    {
        //wrong in label
        throw DOG_EXCEPTION(array_to_view(ERROR_OAEP_INVALID));
    }
    return DB.sub_bytes_pos(start + 1, DB.cend());
}

NSROOT::OAEP::OAEP(const HashAlg& alg, uint64_t key_size, const BinaryData& label)
    :t_alg_p_(alg.clone()), m_alg_p_(nullptr), label_(label), key_size_(key_size)
{}
NSROOT::OAEP::OAEP(const HashAlg& t_alg, const HashAlg& m_alg, uint64_t key_size, const BinaryData& label)
    :t_alg_p_(t_alg.clone()), m_alg_p_(m_alg.clone()), label_(label), key_size_(key_size)
{}
NSROOT::OAEP::OAEP(const OAEP& other)
{
    this->t_alg_p_ = other.t_alg_p_->clone();
    if (other.m_alg_p_) this->m_alg_p_ = other.m_alg_p_->clone();
    this->label_ = other.label_;
    this->key_size_ = other.key_size_;
}
NSROOT::OAEP& NSROOT::OAEP::operator=(const OAEP& other)
{
    if (this == &other) return *this;
    this->t_alg_p_ = other.t_alg_p_->clone();
    if (other.m_alg_p_) this->m_alg_p_ = other.m_alg_p_->clone();
    this->label_ = other.label_;
    this->key_size_ = other.key_size_;
    return *this;
}
NSROOT::OAEP::OAEP(OAEP&& other) noexcept
{
    this->t_alg_p_ = std::move(other.t_alg_p_);
    if (this->m_alg_p_) this->m_alg_p_ = std::move(other.m_alg_p_);
    this->label_ = std::move(other.label_);
    this->key_size_ = other.key_size_;
}
NSROOT::OAEP& NSROOT::OAEP::operator=(OAEP&& other) noexcept
{
    if (this == &other) return *this;
    this->t_alg_p_ = std::move(other.t_alg_p_);
    if (this->m_alg_p_) this->m_alg_p_ = std::move(other.m_alg_p_);
    this->label_ = std::move(other.label_);
    this->key_size_ = other.key_size_;
    return *this;
}

const NSROOT::Config& NSROOT::OAEP::get_allow_config() const
{
    static const Config config = {
        "OAEP",
        std::map<std::string, ParamInfo>{
            { "label",{ ParamType::Binary,"" } }
        },
        std::map<std::string, PrimusType>{
            { "hash", PrimusType::Hash }
        }
    };
    return config;
}
bool NSROOT::OAEP::check(const algorithm::Algorithm& alg)
{
    if (alg.get_config().name != "RSA" && alg.key_size == 512)
    {
        throw DOG_EXCEPTION(array_to_view(ERROR_OAEP_INVALID));
    }
    return true;
}
NSROOT::Config NSROOT::OAEP::get_config() const
{
    return OAEP::get_allow_config();
}
std::unique_ptr<NSROOT::Padding> NSROOT::OAEP::clone() const
{
    return std::make_unique<OAEP>(*this);
}

NSROOT::padding_func NSROOT::OAEP::get_padding() const
{
    if (m_alg_p_ == nullptr)
    {
        return [this](const BinaryData& plain)->BinaryData
            {
                return padding(plain, this->key_size_, this->label_, *(this->t_alg_p_));
            };
    }
    else
    {
        return [this](const BinaryData& plain)->BinaryData
            {
                return padding(plain, this->key_size_, this->label_, *(this->t_alg_p_), *(this->m_alg_p_));
            };
    }
}
NSROOT::padding_func NSROOT::OAEP::get_unpadding() const
{
    if (m_alg_p_ == nullptr)
    {
        return [this](const BinaryData& crypt)->BinaryData
            {
                return unpadding(crypt, this->key_size_, this->label_, *(this->t_alg_p_));
            };
    }
    else
    {
        return [this](const BinaryData& crypt)->BinaryData
            {
                return unpadding(crypt, this->key_size_, this->label_, *(this->t_alg_p_), *(this->m_alg_p_));
            };
    }
}
