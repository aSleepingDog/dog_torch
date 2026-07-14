#include "crypto/asym/algorithms/RSA.h"

namespace NSROOT = dog_torch::crypto::asym::algorithm;
using dog_torch::serialize::BinaryData;
using KeyPair = dog_torch::crypto::asym::KeyPair;
using dog_torch::utils::tp_string;
using dog_torch::utils::from_c_str;
using dog_torch::utils::from_uint64;
using dog_torch::utils::operator+;
using dog_torch::utils::array_to_view;

constexpr auto ERROR_INVALID_KEY = from_c_str("invalid key");
constexpr auto ERROR_TO_LARGE = from_c_str("input is bigger than key");

NSROOT::RSA::RSA(uint32_t public_key) : public_key_(public_key)
{}

KeyPair NSROOT::RSA::create_key_pair(uint64_t key_size, uint64_t public_key)
{
    /*
    * 64   =  512    r-0.5s
    * 128  =  1024   r-1.5s
    * 256  =  2048   r-5s
    * 384  =  3072   r-15s 21s
    * 512  =  4096   r-40s
    */
    using BigUInt = dog_torch::math::number::BigUnsignedInteger;
    using dog_torch::serialize::tlv::Value;
    using dog_torch::math::number_theory::generate_prime;
    using dog_torch::math::number_theory::exgcd_inverse;
    BigUInt e = public_key;
    //std::cout << std::format("e:{}", e.to_num_str(10)) << std::endl;
    BigUInt p = generate_prime(key_size, public_key);
    //std::cout << std::format("p:{}", p.to_num_str(10)) << std::endl;
    BigUInt q = generate_prime(key_size, public_key);
    //std::cout << std::format("q:{}", q.to_num_str(10)) << std::endl;
    BigUInt n = p * q;
    //std::cout << std::format("n:{}", n.to_num_str(10)) << std::endl;
    BigUInt t = n - p - q + 1;
    BigUInt d = exgcd_inverse(e, t);
    //std::cout << std::format("d:{}", d.to_num_str(10)) << std::endl;
    Value pub_collect = std::vector<Value>{};
    pub_collect.to_array().reserve(2);
    pub_collect.to_array().push_back(Value(n.to_bytes(true)));
    pub_collect.to_array().push_back(Value(e.to_bytes(true)));
    Value pri_collect = std::vector<Value>{};
    pri_collect.to_array().reserve(5);
    pri_collect.to_array().push_back(Value(p.to_bytes(true)));
    pri_collect.to_array().push_back(Value(q.to_bytes(true)));
    pri_collect.to_array().push_back(Value(e.to_bytes(true)));
    pri_collect.to_array().push_back(Value(n.to_bytes(true)));
    pri_collect.to_array().push_back(Value(d.to_bytes(true)));
    return { pub_collect.serialize(), pri_collect.serialize() };
}

BinaryData NSROOT::RSA::encrypt(const BinaryData& plain, const BinaryData& key, uint64_t size)
{
    if (size != 64 && size != 128 && size != 256 && size != 384 && size != 512)
    {
        throw DOG_EXCEPTION(ERROR_INVALID_KEY.data());
    }
    using BigUInt = dog_torch::math::number::BigUnsignedInteger;
    using dog_torch::math::number_theory::power_remainder;
    using dog_torch::serialize::tlv::Value;
    auto pos = key.cbegin();
    Value k_v = Value::parse(pos, key.cend());
    BigUInt n = BigUInt::from_bytes(k_v.to_array()[0].to_binary(), true);
    //std::cout << std::format("n:{}", n.to_num_str(10)) << std::endl;
    BigUInt e = BigUInt::from_bytes(k_v.to_array()[1].to_binary(), true);
    //std::cout << std::format("e:{}", e.to_num_str(10)) << std::endl;
    BigUInt p = BigUInt::from_bytes(plain.get_data(), false);
    if (p > n)
        throw DOG_EXCEPTION(array_to_view(ERROR_TO_LARGE));
    //std::cout << std::format("p:{}", p.to_num_str(10)) << std::endl;
    BigUInt c = power_remainder(p, e, n);
    //std::cout << std::format("c:{}", c.to_num_str(10)) << std::endl;
    return BinaryData(c.to_bytes(false));
}
BinaryData NSROOT::RSA::decrypt(const BinaryData& crypt, const BinaryData& key, uint64_t size)
{
    if (size != 64 && size != 128 && size != 256 && size != 384 && size != 512)
    {
        throw DOG_EXCEPTION(ERROR_INVALID_KEY.data());
    }
    using BigUInt = dog_torch::math::number::BigUnsignedInteger;
    using dog_torch::math::number_theory::power_remainder;
    using dog_torch::serialize::tlv::Value;
    auto pos = key.cbegin();
    Value k_v = Value::parse(pos, key.cend());
    BigUInt n = BigUInt::from_bytes(k_v.to_array()[3].to_binary(), true);
    //std::cout << std::format("n:{}", n.to_num_str(10)) << std::endl;
    BigUInt d = BigUInt::from_bytes(k_v.to_array()[4].to_binary(), true);
    //std::cout << std::format("d:{}", d.to_num_str(10)) << std::endl;
    BigUInt c = BigUInt::from_bytes(crypt.get_data(), false);
    if (c > n)
        throw DOG_EXCEPTION(array_to_view(ERROR_TO_LARGE));
    //std::cout << std::format("c:{}", c.to_num_str(10)) << std::endl;
    BigUInt p = power_remainder(c, d, n);
    //std::cout << std::format("p:{}", p.to_num_str(10)) << std::endl;
    return BinaryData(p.to_bytes(false));
}

std::unique_ptr<NSROOT::Algorithm> NSROOT::RSA::clone() const
{
    return std::make_unique<NSROOT::RSA>(*this);
}

KeyPair NSROOT::RSA::generate_key_pair(uint64_t key_size) const
{
    return RSA::create_key_pair(key_size, this->public_key_);
}
NSROOT::crypt_func NSROOT::RSA::get_encrypt_func() const
{
    return crypt_func();
}
NSROOT::crypt_func NSROOT::RSA::get_decrypt_func() const
{
    return crypt_func();
}
