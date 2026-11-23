#include "crypto/asym/algorithms/RSA.h"
#include "error_msg.h"

namespace NSROOT = dog_torch::crypto::asym::algorithm;
using dog_torch::serialize::BinaryData;
using KeyPair = dog_torch::crypto::asym::KeyPair;

NSROOT::RSA::RSA(uint64_t key_size, uint32_t public_key) : Algorithm(key_size), public_key_(public_key) {}

KeyPair NSROOT::RSA::create_key_pair(uint64_t key_size, uint64_t public_key)
{
    /*
    * 64   =  512    r-0.5s
    * 128  =  1024   r-1.5s
    * 256  =  2048   r-5s
    * 384  =  3072   r-15s 21s
    * 512  =  4096   r-40s
    */
    key_size /= 16;
    using BigUInt = dog_torch::math::number::BigUnsignedInteger;
    using BigInt = dog_torch::math::number::BigInteger;
    using dog_torch::serialize::asn1::Value;
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
    BigUInt b = exgcd_inverse(q, p) % p;
    //std::cout << std::format("d:{}", d.to_num_str(10)) << std::endl;
    /**
         RSAPublicKey ::= SEQUENCE {
             modulus           INTEGER,  -- n
             publicExponent    INTEGER   -- e
         }
    */
    Value pub_collect = std::vector<Value>{};
    pub_collect.to_sequence().reserve(2);
    pub_collect.to_sequence().emplace_back(Value{ n });
    pub_collect.to_sequence().emplace_back(Value{ e });
    /**
        Version ::= INTEGER { two-prime(0), multi(1) }
           (CONSTRAINED BY
           {-- version must be multi if otherPrimeInfos present --})
     RSAPrivateKey ::= SEQUENCE {
         0 version           Version,
         1 modulus           INTEGER,  -- n
         2 publicExponent    INTEGER,  -- e
         3 privateExponent   INTEGER,  -- d
         4 prime1            INTEGER,  -- p
         5 prime2            INTEGER,  -- q
         6 exponent1         INTEGER,  -- d mod (p-1)
         7 exponent2         INTEGER,  -- d mod (q-1)
         8 coefficient       INTEGER,  -- (inverse of q) mod p
         9 otherPrimeInfos   OtherPrimeInfos OPTIONAL
     }
*/
    Value pri_collect = std::vector<Value>{};
    pri_collect.to_sequence().reserve(10);
    pri_collect.to_sequence().emplace_back(Value{ BigInt{0,0} });//two prime
    pri_collect.to_sequence().emplace_back(Value{ n });
    pri_collect.to_sequence().emplace_back(Value{ e });
    pri_collect.to_sequence().emplace_back(Value{ d });
    pri_collect.to_sequence().emplace_back(Value{ p });
    pri_collect.to_sequence().emplace_back(Value{ q });
    pri_collect.to_sequence().emplace_back(Value{ d % (p - 1) });
    pri_collect.to_sequence().emplace_back(Value{ d % (q - 1) });
    pri_collect.to_sequence().emplace_back(Value{ b });
    pri_collect.to_sequence().emplace_back(Value{ std::vector<Value>{} });
    /*
-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----
-----BEGIN RSA PUBLIC KEY-----
-----END RSA PUBLIC KEY-----
    */
    return { pub_collect.serialize(), pri_collect.serialize() };
}

BinaryData NSROOT::RSA::encrypt(const BinaryData& plain, const BinaryData& key, uint64_t size)
{
    if (size != 512 && size != 1024 && size != 2048 && size != 3072 && size != 4096)
    {
        throw DOG_EXCEPTION(ERROR_RSA_INVALID_KEY.data());
    }
    using BigUInt = dog_torch::math::number::BigUnsignedInteger;
    using dog_torch::math::number_theory::power_remainder;
    using dog_torch::serialize::asn1::Value;
    auto pos = key.cbegin();
    Value k_v = Value::parse(pos, key.cend());
    BigUInt n = k_v.to_sequence()[0].to_integer().num_;
    //std::cout << std::format("n:{}", n.to_num_str(10)) << std::endl;
    BigUInt e = k_v.to_sequence()[1].to_integer().num_;
    //std::cout << std::format("e:{}", e.to_num_str(10)) << std::endl;
    BigUInt p = BigUInt::from_bytes(plain.get_data(), false);
    if (p > n)
        throw DOG_EXCEPTION(array_to_view(ERROR_RSA_TO_LARGE));
    //std::cout << std::format("p:{}", p.to_num_str(10)) << std::endl;
    BigUInt c = power_remainder(p, e, n);
    using dog_torch::math::integer::available_size;
    // size is in bits; k is the modulus size in bytes.
    // `total` is the byte length of c (available_size returns bytes).
    uint64_t k = size / 8;
    uint64_t total = (c.num_.size() - 1) * 8 + available_size(c.num_.back());
    //std::cout << std::format("c:{}", c.to_num_str(10)) << std::endl;
    if (total == k)
    {
        return BinaryData(c.to_bytes(false));
    }
    else
    {
        BinaryData result;
        result.resize(k);
        auto t = c.to_bytes(false);
        std::copy(t.cbegin(), t.cend(), result.begin() + (k - t.size()));
        return result;
    }
}
BinaryData NSROOT::RSA::decrypt(const BinaryData& crypt, const BinaryData& key, uint64_t size)
{
    if (size != 512 && size != 1024 && size != 2048 && size != 3072 && size != 4096)
    {
        throw DOG_EXCEPTION(ERROR_RSA_INVALID_KEY.data());
    }
    using BigUInt = dog_torch::math::number::BigUnsignedInteger;
    using dog_torch::math::number_theory::power_remainder;
    using dog_torch::serialize::asn1::Value;
    auto pos = key.cbegin();
    Value k_v = Value::parse(pos, key.cend());
    BigUInt n = k_v.to_sequence()[1].to_integer().num_;
    //std::cout << std::format("n:{}", n.to_num_str(10)) << std::endl;
    BigUInt d = k_v.to_sequence()[3].to_integer().num_;
    //std::cout << std::format("d:{}", d.to_num_str(10)) << std::endl;
    BigUInt c = BigUInt::from_bytes(crypt.get_data(), false);
    if (c > n)
        throw DOG_EXCEPTION(array_to_view(ERROR_RSA_TO_LARGE));
    //std::cout << std::format("c:{}", c.to_num_str(10)) << std::endl;
    BigUInt p = power_remainder(c, d, n);
    //std::cout << std::format("p:{}", p.to_num_str(10)) << std::endl;
    return BinaryData(p.to_bytes(false));
}

std::unique_ptr<NSROOT::Algorithm> NSROOT::RSA::clone() const
{
    return std::make_unique<NSROOT::RSA>(*this);
}

const NSROOT::Config& NSROOT::RSA::get_allow_config() const
{
    static const Config config = Config{
        "RSA","512,1024,2048,3072,4096",
        std::map<std::string, ParamInfo>{}
    };
    return config;
}

NSROOT::Config NSROOT::RSA::get_config() const
{
    return RSA::get_allow_config();
}

KeyPair NSROOT::RSA::generate_key_pair() const
{
    return RSA::create_key_pair(this->key_size, this->public_key_);
}
NSROOT::crypt_func NSROOT::RSA::get_encrypt_func() const
{
    return [this](const BinaryData& plain, const BinaryData& key)
        {
            return RSA::encrypt(plain, key, this->key_size);
        };
}
NSROOT::crypt_func NSROOT::RSA::get_decrypt_func() const
{
    return [this](const BinaryData& crypt, const BinaryData& key)
        {
            return RSA::decrypt(crypt, key, this->key_size);
        };
}
