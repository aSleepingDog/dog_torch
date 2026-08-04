#include "crypto/asym/algorithms/RSA.h"

namespace NSROOT = dog_torch::crypto::asym::algorithm;
using dog_torch::serialize::BinaryData;
using KeyPair = dog_torch::crypto::asym::KeyPair;
using dog_torch::utils::tp_string;
using dog_torch::utils::from_c_str;
using dog_torch::utils::from_uint64;
using dog_torch::utils::operator+;
using dog_torch::utils::array_to_view;

constexpr auto ERROR_INVALID_KEY = from_c_str("RSA:invalid key");
constexpr auto ERROR_TO_LARGE = from_c_str("RSA: input is bigger than key");
constexpr auto ERROR_OAEP_INVALID = from_c_str("RSA OAEP:invalid OAEP padding");

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
    key_size /= 2;
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
    return { pub_collect.serialize(), pri_collect.serialize() };
}
static BinaryData MGF1(const BinaryData& data, uint64_t output, const dog_torch::crypto::hash::algorithm::Algorithm& alg)
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
void NSROOT::RSA::OAEP_padding(BinaryData& plain, uint64_t key_size, const BinaryData& label, const dog_torch::crypto::hash::algorithm::Algorithm& alg)
{
    uint64_t hlen = alg.get_out_size();
    uint64_t mlen = plain.size();
    if (mlen > key_size - 2 * hlen - 2)
    {
        throw DOG_EXCEPTION(array_to_view(ERROR_TO_LARGE));
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
    std::random_device rd;
    while (seed.size() < hlen)
    {
        seed.push_back(rd());
    }
    //std::cout << "seed:" << seed.to_hex_string(true) << std::endl;
    BinaryData maskedDB = MGF1(seed, key_size - hlen - 1, alg) ^ DB;
    //std::cout << "maskedDB:" << maskedDB.to_hex_string(true) << std::endl;
    BinaryData maskedSeed = MGF1(maskedDB, hlen, alg) ^ seed;
    //std::cout << "maskedSeed:" << maskedSeed.to_hex_string(true) << std::endl;
    plain.clear();
    plain.push_back(0x00);
    plain += maskedSeed;
    plain += maskedDB;
}
void NSROOT::RSA::OAEP_unpadding(BinaryData & crypt, uint64_t key_size, const BinaryData& label, const dog_torch::crypto::hash::algorithm::Algorithm& alg)
{
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
    crypt = DB.sub_bytes_pos(start + 1, DB.cend());
}

BinaryData NSROOT::RSA::encrypt(const BinaryData& plain, const BinaryData& key, uint64_t size, std::function<void(BinaryData&)> padding)
{
    if (size != 64 && size != 128 && size != 256 && size != 384 && size != 512)
    {
        throw DOG_EXCEPTION(ERROR_INVALID_KEY.data());
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
        throw DOG_EXCEPTION(array_to_view(ERROR_TO_LARGE));
    //std::cout << std::format("p:{}", p.to_num_str(10)) << std::endl;
    BigUInt c = power_remainder(p, e, n);
    using dog_torch::math::integer::available_size;
    uint64_t total = (c.num_.size() - 1) * 8 + available_size(c.num_.back());
    //std::cout << std::format("c:{}", c.to_num_str(10)) << std::endl;
    if (total == size)
    {
        return BinaryData(c.to_bytes(false));
    }
    else
    {
        BinaryData result;
        result.resize(size);
        auto t = c.to_bytes(false);
        std::copy(t.cbegin(), t.cend(), result.begin() + (size - t.size()));
        return result;
    }
}
BinaryData NSROOT::RSA::decrypt(const BinaryData& crypt, const BinaryData& key, uint64_t size, std::function<void(BinaryData&)> unpadding)
{
    if (size != 64 && size != 128 && size != 256 && size != 384 && size != 512)
    {
        throw DOG_EXCEPTION(ERROR_INVALID_KEY.data());
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

const NSROOT::Config& NSROOT::RSA::get_allow_config() const
{
    static const Config config = Config{
        "RSA","64,128,256,384,512",
        std::map<std::string, ParamInfo>{
            {"padding",         ParamInfo{ParamType::String, "opinion:\"\",\"PKCS1\",\"OAEP\""}},
            {"OAEP_hash",       ParamInfo{ParamType::Hash,   "only effective in OAEP padding"}},
            {"OAEP_label",      ParamInfo{ParamType::String, "only effective in OAEP padding"}}
        }
    };
    return config;
}

NSROOT::Config NSROOT::RSA::get_config() const
{
    return RSA::get_allow_config();
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
