#include "crypto/hash/algorithms/BLAKE.h"

namespace NSROOT = dog_torch::crypto::hash::algorithm;
using dog_torch::serialize::BinaryData;

using dog_torch::utils::from_c_str;
using dog_torch::serialize::from_hex;
using dog_torch::utils::from_uint64;
using dog_torch::utils::array_to_view;

constexpr auto ERROR_OUTPUT_SIZE = from_c_str("BsLAKE2: Invalid output size");
constexpr auto ERROR_KEY_SIZE = from_c_str("BLAKE2: Invalid key size");
constexpr auto ERROR_EFFECTIVE = from_c_str("BLAKE2: only support 64 for BLAKE2b and 32 for BLAKE2s");

const NSROOT::Config& NSROOT::BLAKE2::allowed_config()
{
    static auto config = Config("BLAKE2", "32,64", {
        {"out_size",ParamType::UInt64},
        {"key",ParamType::Binary},
        {"salt",ParamType::Binary},
        {"personalization",ParamType::Binary} 
        });
    return config;
}

NSROOT::BLAKE2::BLAKE2(uint64_t effective, uint8_t out_size, const BinaryData& key, const BinaryData& salt, const BinaryData& personalization)
    : Algorithm(effective), out_size(out_size), key(key)
{
    uint64_t i = 0;
    if (this->effective == 64)
    {
        this->p.resize(64);
        if (out_size == 0) this->out_size = static_cast<uint8_t>(this->effective);
        else if (out_size > this->effective) throw DOG_EXCEPTION(array_to_view(ERROR_OUTPUT_SIZE));
        else this->out_size = out_size;
        this->p[0] = this->out_size;//Digest len
        if (this->key.size() > this->effective) throw DOG_EXCEPTION(array_to_view(ERROR_KEY_SIZE));
        if (this->key.size() > 0) this->key.resize(128), this->t_low = 128;
        this->p[1] = static_cast<uint8_t>(key.size());//Key len
        this->p[2] = 1;//Fanout
        this->p[3] = 1;//Depth
        //for (i = 0; i < 4; i++) this->p.push_back(0);//Leaf length
        //for (i = 0; i < 8; i++) this->p.push_back(0);//Node offset
        //this->p.push_back(0);//Node depth
        //this->p.push_back(0);//Inner length
        //for (i = 0; i < 14; i++) this->p.push_back(0);//Reserved
        for (i = 0; i < 28; ++i) this->p[i + 4] = 0;//all of above
        i = 32;
        for (auto cit = salt.cbegin(); cit != salt.cend() && i < 48; ++cit, ++i)
        {
            this->p[i] = *cit;
        }
        for (auto cit = personalization.cbegin(); cit != personalization.cend() && i < 64; ++cit, ++i)
        {
            this->p[i] = *cit;
        }

        for (auto it1 = this->p.begin(); it1 != this->p.end(); it1 += 8)
        {
            for (uint8_t i = 0; i < 4; ++i)
            {
                std::swap(*(it1 + i), *(it1 + (7 - i)));
            }
        }
    }
    else if (this->effective == 32)
    {
        this->p.resize(32);
        if (out_size == 0) this->out_size = static_cast<uint8_t>(this->effective);
        else if (out_size > this->effective) throw DOG_EXCEPTION(array_to_view(ERROR_OUTPUT_SIZE));
        else this->out_size = out_size;
        this->p[0] = this->out_size;//Digest len
        if (this->key.size() > this->effective) throw DOG_EXCEPTION(array_to_view(ERROR_KEY_SIZE));
        if (this->key.size() > 0) this->key.resize(64), this->t_low = 64;
        this->p[1] = static_cast<uint8_t>(key.size());//Key len
        this->p[2] = 1;//Fanout
        this->p[3] = 1;//Depth
        //for (i = 0; i < 4; i++) this->p.push_back(0);//Leaf length        
        //for (i = 0; i < 6; i++) this->p.push_back(0);//Node offset
        //this->p.push_back(0);//Node depth
        //this->p.push_back(0);//Inner length
        for (i = 0; i < 12; i++) this->p[i + 4] = 0;//all of above
        i = 16;
        for (auto cit = salt.cbegin(); cit != salt.cend() && i < 24; ++cit, ++i)
        {
            this->p[i] = *cit;
        }
        for (auto cit = personalization.cbegin(); cit != personalization.cend() && i < 32; ++cit, ++i)
        {
            this->p[i] = *cit;
        }

        for (auto it1 = this->p.begin(); it1 != this->p.end(); it1 += 4)
        {
            for (uint8_t i = 0; i < 2; ++i)
            {
                std::swap(*(it1 + i), *(it1 + (3 - i)));
            }
        }
    }
    else throw DOG_EXCEPTION(array_to_view(ERROR_EFFECTIVE));
    //std::cout << this->p.to_hex_string(true) << std::endl;
}

NSROOT::BLAKE2::BLAKE2(const BLAKE2& other) : Algorithm(other)
{
    this->t_low = other.t_low;
    this->f0 = other.f0;
    this->out_size = other.out_size;
    this->key = other.key;
    this->p = other.p;
}
NSROOT::BLAKE2& NSROOT::BLAKE2::operator=(const BLAKE2& other)
{
    Algorithm::operator=(other);
    this->t_low = other.t_low;
    this->f0 = other.f0;
    this->out_size = other.out_size;
    this->key = other.key;
    this->p = other.p;
    return *this;
}
NSROOT::BLAKE2::BLAKE2(BLAKE2&& other) noexcept : Algorithm(std::move(other))
{
    this->t_low = other.t_low;
    this->f0 = other.f0;
    this->out_size = other.out_size;
    this->key = std::move(other.key);
    this->p = std::move(other.p);
}
NSROOT::BLAKE2& NSROOT::BLAKE2::operator=(BLAKE2&& other) noexcept
{
    if (this ==&other) return *this;
    Algorithm::operator=(std::move(other));
    this->t_low = other.t_low;
    this->f0 = other.f0;
    this->out_size = other.out_size;
    this->key = std::move(other.key);
    this->p = std::move(other.p);
    return *this;
}

const std::array<uint8_t, 32> NSROOT::BLAKE2::IV_32 = from_hex("6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19");
const std::array<uint8_t, 64> NSROOT::BLAKE2::IV_64 = from_hex("6A09E667F3BCC908BB67AE8584CAA73B3C6EF372FE94F82BA54FF53A5F1D36F1510E527FADE682D19B05688C2B3E6C1F1F83D9ABFB41BD6B5BE0CD19137E2179");

uint8_t NSROOT::BLAKE2::Sigma[12][16] = {
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 },
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

NSROOT::Config NSROOT::BLAKE2::config() const
{
    return BLAKE2::allowed_config();
}

std::string NSROOT::BLAKE2::fmt_string() const
{
    return std::format("{}({})", this->config().name, this->effective);
}

void NSROOT::BLAKE2::init()
{
    this->f0 = 0;
    this->t_low = this->key.size();
}

BinaryData NSROOT::BLAKE2::init_data() const
{
    BinaryData hash;
    if (this->effective == 64)
    {
        hash = BinaryData(IV_64) ^ this->p;
        if (this->key.size() != 0) update_64(this->key, hash, this->t_low, this->f0);
    }
    else if (this->effective == 32)
    {
        hash = BinaryData(IV_32) ^ this->p;
        if (this->key.size() != 0) update_32(this->key, hash, static_cast<uint32_t>(this->t_low), static_cast<uint32_t>(this->f0));
    }
    return hash;
}
NSROOT::update_func NSROOT::BLAKE2::get_update() const
{
    return [this](const BinaryData& block, BinaryData& value)->void
        {
            if (this->effective == 64)
                update_64(block, value, this->t_low, this->f0);
            else if (this->effective == 32)
                update_32(block, value, static_cast<uint32_t>(this->t_low), static_cast<uint32_t>(this->f0));
        };
}
NSROOT::trims_func NSROOT::BLAKE2::get_trims() const
{
    return [this](BinaryData& input) -> void
        {
            if (this->key.size() != 0 && ((this->effective == 64 && this->t_low == 128) || (this->effective == 32 && this->t_low == 64)))
            {
                BinaryData hash;
                if (this->effective == 64 && this->t_low == 128)
                {
                    hash = BinaryData(IV_64) ^ this->p;
                    update_64(this->key, hash, 128, UINT64_MAX);
                }
                else if (this->effective == 32 && this->t_low == 64)
                {
                    hash = BinaryData(IV_32) ^ this->p;
                    update_32(this->key, hash, 64, UINT32_MAX);
                }
                input = hash;
            }
            for (auto it = input.begin(); it != input.end(); it += this->effective / 8)
            {
                for (uint64_t i = 0; i < this->effective / 8 / 2; ++i)
                {
                    std::swap(*(it + i), *(it + (this->effective / 8 - i - 1)));
                }
            }
            input.resize(this->out_size);
        };
}
uint64_t NSROOT::BLAKE2::get_block_size() const
{
    return this->effective * 2;
}
uint64_t NSROOT::BLAKE2::get_out_size() const
{
    return this->out_size;
}
std::unique_ptr<NSROOT::Algorithm> NSROOT::BLAKE2::clone() const
{
    return std::make_unique<BLAKE2>(*this);
}

bool NSROOT::BLAKE2::have_next_block(uint64_t data_pos, uint64_t data_total)
{
    return data_total - data_pos > 0;
}

BinaryData NSROOT::BLAKE2::next_block(const BinaryData& data, uint64_t start, uint64_t& data_pos, uint64_t data_total)
{
    using dog_torch::serialize::stream::read_bytes;
    BinaryData buffer;
    uint64_t num = 0;
    data_pos += start;
    read_bytes(data, data_total, data_pos, buffer, this->effective * 2, num);
    this->t_low += num;
    buffer.resize(this->effective * 2);
    data_pos -= start;
    if (data_pos == data_total) this->f0 = UINT64_MAX;
    return buffer;
}

BinaryData NSROOT::BLAKE2::next_block(std::istream& data, uint64_t& data_pos, uint64_t data_total)
{
    using dog_torch::serialize::stream::read_bytes;
    BinaryData buffer;
    uint64_t num = 0;
    read_bytes(data, data_total, data_pos, buffer, this->effective * 2, num);
    this->t_low += num;
    buffer.resize(this->effective * 2);
    if (data_pos == data_total) this->f0 = UINT64_MAX;
    return buffer;
}

void NSROOT::BLAKE2::g_64(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d, uint64_t m0, uint64_t m1)
{
    using dog_torch::math::integer::uirotr;
    a += b + m0;
    d = uirotr(d ^ a, 32);
    c += d;
    b = uirotr(b ^ c, 24);
    a += b + m1;
    d = uirotr(d ^ a, 16);
    c += d;
    b = uirotr(b ^ c, 63);
}
void NSROOT::BLAKE2::update_64(const BinaryData& block, BinaryData& value, uint64_t t_low, uint64_t f0)
{
    std::array<uint64_t, 8> h = { 0 };
    for (uint8_t i = 0; i < 8; ++i)
    {
        for (uint8_t j = 0; j < 8; ++j)
        {
            h[i] |= static_cast<uint64_t>(value[i * 8 + j]) << (56 - (j * 8));
        }
    }
    auto h0 = h;
    uint64_t m[16] = { 0 };
    for (uint8_t i = 0; i < 16; ++i)
    {
        for (uint8_t j = 0; j < 8; ++j)
        {
            m[i] |= static_cast<uint64_t>(block[i * 8 + (7 - j)]) << (56 - (j * 8));
        }
    }
    uint64_t iv[8] = {
        0x6A09E667F3BCC908,
        0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1,
        0x510E527FADE682D1,
        0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B,
        0x5BE0CD19137E2179
    };
    iv[4] ^= t_low;
    iv[6] ^= f0;
    for (uint8_t i = 0; i < 12; ++i)
    {
        g_64(h[0], h[4], iv[0], iv[4], m[Sigma[i][0]], m[Sigma[i][1]]);
        g_64(h[1], h[5], iv[1], iv[5], m[Sigma[i][2]], m[Sigma[i][3]]);
        g_64(h[2], h[6], iv[2], iv[6], m[Sigma[i][4]], m[Sigma[i][5]]);
        g_64(h[3], h[7], iv[3], iv[7], m[Sigma[i][6]], m[Sigma[i][7]]);
        g_64(h[0], h[5], iv[2], iv[7], m[Sigma[i][8]], m[Sigma[i][9]]);
        g_64(h[1], h[6], iv[3], iv[4], m[Sigma[i][10]], m[Sigma[i][11]]);
        g_64(h[2], h[7], iv[0], iv[5], m[Sigma[i][12]], m[Sigma[i][13]]);
        g_64(h[3], h[4], iv[1], iv[6], m[Sigma[i][14]], m[Sigma[i][15]]);
    }
    for (uint8_t i = 0; i < 8; ++i)
    {
        h[i] = h0[i] ^ h[i] ^ iv[i];
    }
    for (uint8_t i = 0; i < 8; ++i)
    {
        for (uint8_t j = 0; j < 8; ++j)
        {
            value[i * 8 + j] = static_cast<uint8_t>(h[i] >> (56 - (j * 8)));
        }
    }
}
void NSROOT::BLAKE2::g_32(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t m0, uint32_t m1)
{
    using dog_torch::math::integer::uirotr;
    a += b + m0;
    d = uirotr(d ^ a, 16);
    c += d;
    b = uirotr(b ^ c, 12);
    a += b + m1;
    d = uirotr(d ^ a, 8);
    c += d;
    b = uirotr(b ^ c, 7);
}
void NSROOT::BLAKE2::update_32(const BinaryData& block, BinaryData& value, uint32_t t_low, uint32_t f0)
{
    std::array<uint32_t, 8> h = { 0 };
    for (uint8_t i = 0; i < 8; ++i)
    {
        for (uint8_t j = 0; j < 4; ++j)
        {
            h[i] |= static_cast<uint32_t>(value[i * 4 + j]) << (24 - (j * 8));
        }
    }
    auto h0 = h;
    uint32_t m[16] = { 0 };
    for (uint8_t i = 0; i < 16; ++i)
    {
        for (uint8_t j = 0; j < 4; ++j)
        {
            m[i] |= static_cast<uint32_t>(block[i * 4 + (3 - j)]) << (24 - (j * 8));
        }
    }
    uint32_t iv[8] = {
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19
    };
    iv[4] ^= t_low;
    iv[6] ^= f0;
    for (uint8_t i = 0; i < 10; ++i)
    {
        g_32(h[0], h[4], iv[0], iv[4], m[Sigma[i][0]], m[Sigma[i][1]]);
        g_32(h[1], h[5], iv[1], iv[5], m[Sigma[i][2]], m[Sigma[i][3]]);
        g_32(h[2], h[6], iv[2], iv[6], m[Sigma[i][4]], m[Sigma[i][5]]);
        g_32(h[3], h[7], iv[3], iv[7], m[Sigma[i][6]], m[Sigma[i][7]]);
        g_32(h[0], h[5], iv[2], iv[7], m[Sigma[i][8]], m[Sigma[i][9]]);
        g_32(h[1], h[6], iv[3], iv[4], m[Sigma[i][10]], m[Sigma[i][11]]);
        g_32(h[2], h[7], iv[0], iv[5], m[Sigma[i][12]], m[Sigma[i][13]]);
        g_32(h[3], h[4], iv[1], iv[6], m[Sigma[i][14]], m[Sigma[i][15]]);
    }
    for (uint8_t i = 0; i < 8; ++i)
    {
        h[i] = h0[i] ^ h[i] ^ iv[i];
    }
    for (uint8_t i = 0; i < 8; ++i)
    {
        for (uint8_t j = 0; j < 4; ++j)
        {
            value[i * 4 + j] = static_cast<uint8_t>(h[i] >> (24 - (j * 8)));
        }
    }
}

#define NAMESPACE(name) dog_torch__crypto__hash__SHA2_##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

SERIALIZE(BinaryData)* NS_BLAKE2(64_binary) (const LVALUE(SERIALIZE(BinaryData))data, uint64_t effective, uint8_t out_size, const LVALUE(SERIALIZE(BinaryData))key, const LVALUE(SERIALIZE(BinaryData))salt, const LVALUE(SERIALIZE(BinaryData)) personalization)
{
    BinaryData data_ = data == nullptr ? BinaryData() : *data;
    BinaryData key_ = key == nullptr ? BinaryData() : *key;
    BinaryData salt_ = salt == nullptr ? BinaryData() : *salt;
    BinaryData personalization_ = personalization == nullptr ? BinaryData() : *personalization;

    using dog_torch::crypto::hash::algorithm::BLAKE2;
    BLAKE2 alg = BLAKE2(64, out_size, key_, salt_, personalization_);
    alg.init();
    BinaryData* hash_value = new BinaryData(alg.init_data());
    auto update_func = alg.get_update();
    auto trims_func = alg.get_trims();
    uint64_t pos = 0;
    uint64_t total = data_.size();
    do
    {
        BinaryData block = alg.next_block(data_, pos, pos, total);
        update_func(block, *hash_value);
    } while (alg.have_next_block(pos, total));
    trims_func(*hash_value);
    return hash_value;
}

SERIALIZE(BinaryData)* NS_BLAKE2(32_binary) (const LVALUE(SERIALIZE(BinaryData))data, uint64_t effective, uint8_t out_size, const LVALUE(SERIALIZE(BinaryData))key, const LVALUE(SERIALIZE(BinaryData))salt, const LVALUE(SERIALIZE(BinaryData)) personalization)
{
    BinaryData data_ = data == nullptr ? BinaryData() : *data;
    BinaryData key_ = key == nullptr ? BinaryData() : *key;
    BinaryData salt_ = salt == nullptr ? BinaryData() : *salt;
    BinaryData personalization_ = personalization == nullptr ? BinaryData() : *personalization;

    using dog_torch::crypto::hash::algorithm::BLAKE2;
    BLAKE2 alg = BLAKE2(32, out_size, key_, salt_, personalization_);
    alg.init();
    BinaryData* hash_value = new BinaryData(alg.init_data());
    auto update_func = alg.get_update();
    auto trims_func = alg.get_trims();
    uint64_t pos = 0;
    uint64_t total = data_.size();
    do
    {
        BinaryData block = alg.next_block(data_, pos, pos, total);
        update_func(block, *hash_value);
    } while (alg.have_next_block(pos, total));
    trims_func(*hash_value);
    return hash_value;
}

SERIALIZE(BinaryData)* NS_BLAKE2(64_file)(LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(UTILS(CppString)) path, uint64_t effective, uint8_t out_size, const LVALUE(SERIALIZE(BinaryData)) key, const LVALUE(SERIALIZE(BinaryData)) salt, const LVALUE(SERIALIZE(BinaryData)) personalization)
{
    using namespace dog_torch::utils;
    using dog_torch::crypto::hash::algorithm::BLAKE2;
    if (path == nullptr)
    {
        CppResultSet_reset(result_set, -1, "path is null");
        return nullptr;
    }
    std::string path_str = to_string(path);
    if (!std::filesystem::exists(path_str))
    {
        CppResultSet_reset(result_set, -2, "path is not exists");
        return nullptr;
    }
    BinaryData key_ = key == nullptr ? BinaryData() : *key;
    BinaryData salt_ = salt == nullptr ? BinaryData() : *salt;
    BinaryData personalization_ = personalization == nullptr ? BinaryData() : *personalization;

    using dog_torch::crypto::hash::algorithm::BLAKE2;
    BLAKE2 alg = BLAKE2(32, out_size, key_, salt_, personalization_);
    alg.init();
    BinaryData* hash_value = new BinaryData(alg.init_data());
    auto update_func = alg.get_update();
    auto trims_func = alg.get_trims();
    uint64_t pos = 0;
    uint64_t file_size = std::filesystem::file_size(path_str);
    std::ifstream source(path_str, std::ios::binary);
    do
    {
        BinaryData block = alg.next_block(source, pos, file_size);
        update_func(block, *hash_value);
    } while (alg.have_next_block(pos, file_size));
    trims_func(*hash_value);
    return hash_value;
}
SERIALIZE(BinaryData)* NS_BLAKE2(32_file)(LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(UTILS(CppString)) path, uint64_t effective, uint8_t out_size, const LVALUE(SERIALIZE(BinaryData)) key, const LVALUE(SERIALIZE(BinaryData)) salt, const LVALUE(SERIALIZE(BinaryData)) personalization)
{
    using namespace dog_torch::utils;
    using dog_torch::crypto::hash::algorithm::BLAKE2;
    if (path == nullptr)
    {
        CppResultSet_reset(result_set, -1, "path is null");
        return nullptr;
    }
    std::string path_str = to_string(path);
    if (!std::filesystem::exists(path_str))
    {
        CppResultSet_reset(result_set, -2, "path is not exists");
        return nullptr;
    }
    BinaryData key_ = key == nullptr ? BinaryData() : *key;
    BinaryData salt_ = salt == nullptr ? BinaryData() : *salt;
    BinaryData personalization_ = personalization == nullptr ? BinaryData() : *personalization;

    using dog_torch::crypto::hash::algorithm::BLAKE2;
    BLAKE2 alg = BLAKE2(64, out_size, key_, salt_, personalization_);
    alg.init();
    BinaryData* hash_value = new BinaryData(alg.init_data());
    auto update_func = alg.get_update();
    auto trims_func = alg.get_trims();
    uint64_t pos = 0;
    uint64_t file_size = std::filesystem::file_size(path_str);
    std::ifstream source(path_str, std::ios::binary);
    do
    {
        BinaryData block = alg.next_block(source, pos, file_size);
        update_func(block, *hash_value);
    } while (alg.have_next_block(pos, file_size));
    trims_func(*hash_value);
    return hash_value;
}

#undef NAMESPACE
#undef SERIALIZE
#undef UTILS