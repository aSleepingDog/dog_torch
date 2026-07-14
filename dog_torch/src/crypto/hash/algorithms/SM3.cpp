#include "crypto/hash/algorithms/SM3.h"

namespace NSROOT = dog_torch::crypto::hash::algorithm;
using dog_torch::serialize::BinaryData;
using dog_torch::serialize::from_hex;
using dog_torch::utils::from_c_str;

using dog_torch::utils::from_uint64;
using dog_torch::utils::array_to_view;


constexpr auto ERROR_WRONG_BLOCK_SIZE = from_c_str("SM3: block size must be 64 bytes");
constexpr auto ERROR_LARGE_DATA_SIZE = from_c_str("SM3: data size is too large");

uint64_t NSROOT::SM3::max()
{
	return UINT64_MAX >> 3;
}

const NSROOT::Config& NSROOT::SM3::allowed_config()
{
	static auto config = Config("SM3", "32", {});
	return config;
}

NSROOT::SM3::SM3() : Algorithm(32)
{
}
NSROOT::SM3::SM3(const SM3& other) : Algorithm(other)
{
	this->is_padding_80_ = other.is_padding_80_;
	this->is_padding_num_ = other.is_padding_num_;
}
NSROOT::SM3& NSROOT::SM3::operator=(const SM3 & other)
{
	Algorithm::operator=(other);
	this->is_padding_80_ = other.is_padding_80_;
	this->is_padding_num_ = other.is_padding_num_;
	return *this;
}
NSROOT::SM3::SM3(SM3&& other) noexcept : Algorithm(std::move(other))
{
	this->is_padding_80_ = other.is_padding_80_;
	this->is_padding_num_ = other.is_padding_num_;
}
NSROOT::SM3& NSROOT::SM3::operator=(SM3 && other) noexcept
{
	if (this == &other) return *this;
	this->is_padding_80_ = other.is_padding_80_;
	this->is_padding_num_ = other.is_padding_num_;
	return *this;
}
NSROOT::Config NSROOT::SM3::config() const
{
	return SM3::allowed_config();
}
std::string NSROOT::SM3::fmt_string() const
{
	return this->config().name;
}
void NSROOT::SM3::init()
{
    this->is_padding_80_ = false;
    this->is_padding_num_ = false;
}
BinaryData NSROOT::SM3::init_data() const
{
    return IV;
}
NSROOT::update_func NSROOT::SM3::get_update() const
{
    return single_update;
}
NSROOT::trims_func NSROOT::SM3::get_trims() const
{
    return [](serialize::BinaryData& value)->void {};
}
uint64_t NSROOT::SM3::get_block_size() const
{
	return 64;
}
uint64_t NSROOT::SM3::get_out_size() const
{
	return 32;
}
std::unique_ptr<NSROOT::Algorithm> NSROOT::SM3::clone() const
{
    return std::make_unique<SM3>(*this);
}

bool NSROOT::SM3::have_next_block(uint64_t data_pos, uint64_t data_total)
{
	if (data_total > this->max())
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_LARGE_DATA_SIZE));
	}
	auto dur = (data_total - data_pos);
	return dur >= 64 ? true : !this->is_padding_num_;
}
BinaryData NSROOT::SM3::next_block(const BinaryData& data, uint64_t start, uint64_t& data_pos, uint64_t data_total)
{
	if (data_total > this->max())
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_LARGE_DATA_SIZE));
	}
	auto res = data.sub_bytes_len(start, 64);
	data_pos += res.size();
	if (res.size() >= 64) return res;
	else
	{
		if (!this->is_padding_80_)
		{
			res.push_back(0x80);
			this->is_padding_80_ = true;
		}
		if (res.size() > (64 - 8))
		{
			while (res.size() < 64) res.push_back(0x00);
			return res;
		}
		else
		{
			using namespace dog_torch::math::integer;
			while (res.size() < (64 - 8)) res.push_back(0x00);
			uint64_t num = data_total << 3;
			this->is_padding_num_ = true;
			for (uint64_t i = 0; i < 8; i++)
				res.push_back(pick_byte(num, static_cast<uint8_t>(7 - i)));
			return res;
		}
	}
}
BinaryData NSROOT::SM3::next_block(std::istream& data, uint64_t& data_pos, uint64_t data_total)
{
	if (data_total > this->max())
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_LARGE_DATA_SIZE));
	}
	BinaryData res(64);
	data.read((char*)res.data_ptr(), 64);
	for (uint64_t i = data.gcount(); i < 64; i++) res.pop_back();
	data_pos += data.gcount();
	if (res.size() >= 64) return res;
	else
	{
		if (!this->is_padding_80_)
		{
			res.push_back(0x80);
			this->is_padding_80_ = true;
		}
		if (res.size() > (64 - 8))
		{
			while (res.size() < 64) res.push_back(0x00);
			return res;
		}
		else
		{
			using namespace dog_torch::math::integer;
			while (res.size() < (64 - 8)) res.push_back(0x00);
			uint64_t num = data_total << 3;
			this->is_padding_num_ = true;
			for (uint64_t i = 0; i < 8; i++)
				res.push_back(pick_byte(num, static_cast<uint8_t>(7 - i)));
			return res;
		}
	}
}

const std::array<uint8_t, 32> NSROOT::SM3::IV = from_hex("7380166F4914B2B9172442D7DA8A0600A96F30BC163138AAE38DEE4DB0FB0E4E");
uint32_t NSROOT::SM3::tick4B(const BinaryData& data, uint64_t index)
{
    return (uint32_t)(data[4 * index + 0] << 24) + 
           (uint32_t)(data[4 * index + 1] << 16) + 
           (uint32_t)(data[4 * index + 2] << 8) + 
           (uint32_t)(data[4 * index + 3]);
}
uint32_t NSROOT::SM3::P1(const BinaryData& data, uint64_t index)
{
    using namespace dog_torch::math::integer;
    uint32_t w1 = tick4B(data, index - 16);
    uint32_t w2 = tick4B(data, index - 9);
    uint32_t w3 = tick4B(data, index - 3);
    uint32_t w4 = tick4B(data, index - 13);
    uint32_t w5 = tick4B(data, index - 6);
    uint32_t W0 = (w1 ^ w2 ^ (uirotl(w3, 15)));
    uint32_t _P = W0 ^ uirotl(W0, 15) ^ uirotl(W0, 23);
    return _P ^ uirotl(w4, 7) ^ w5;
}
uint32_t NSROOT::SM3::FF1(uint32_t a, uint32_t b, uint32_t c, int i)
{
    if (i < 16)
        return a ^ b ^ c;
    else
        return (a & b) | (a & c) | (b & c);
}
uint32_t NSROOT::SM3::GG1(uint32_t a, uint32_t b, uint32_t c, int i)
{
    if (i < 16)
        return a ^ b ^ c;
    else
        return (a & b) | (~a & c);
}
void NSROOT::SM3::single_update(const BinaryData& block_, BinaryData& value)
{
	if (block_.size() != 64)
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_WRONG_BLOCK_SIZE));
	}
	auto block = block_;
	uint32_t tempN[8], tempH[8];
	for (int i = 0; i < 8; i++)
	{
		uint32_t tempInt = 0;
		tempInt |= (uint32_t)value[i * 4] << 24;
		tempInt |= (uint32_t)value[i * 4 + 1] << 16;
		tempInt |= (uint32_t)value[i * 4 + 2] << 8;
		tempInt |= (uint32_t)value[i * 4 + 3];
		tempN[i] = tempInt;
		tempH[i] = tempInt;
	}
	for (int i0 = 16; i0 < 68; i0++)
	{
		uint32_t W = P1(block, i0);
		for (int i1 = 0; i1 < 4; i1++)
		{
			block.push_back((uint8_t)(W << i1 * 8 >> 24));
		}
	}
	for (int i0 = 0; i0 < 64; i0++)
	{
		uint32_t W = tick4B(block, i0) ^ tick4B(block, i0 + 4);
		for (int i1 = 0; i1 < 4; i1++)
		{
			block.push_back((uint8_t)(W << i1 * 8 >> 24));
		}
	}
	for (int i0 = 0; i0 < 64; i0++)
	{
		using namespace dog_torch::math::integer;
		uint32_t T = (i0 < 16) ? (0x79cc4519) : (0x7a879d8a);
		uint32_t SS1 = uirotl((uirotl(tempN[0], 12) + tempN[4] + uirotl(T, i0)), 7);
		uint32_t SS2 = SS1 ^ uirotl(tempN[0], 12);
		uint32_t TT1 = FF1(tempN[0], tempN[1], tempN[2], i0) + tempN[3] + SS2 + tick4B(block, i0 + 68);
		uint32_t TT2 = GG1(tempN[4], tempN[5], tempN[6], i0) + tempN[7] + SS1 + tick4B(block, i0);
		tempN[3] = tempN[2];
		tempN[2] = uirotl(tempN[1], 9);
		tempN[1] = tempN[0];
		tempN[0] = TT1;
		tempN[7] = tempN[6];
		tempN[6] = uirotl(tempN[5], 19);
		tempN[5] = tempN[4];
		tempN[4] = TT2 ^ uirotl(TT2, 9) ^ uirotl(TT2, 17);
	}
	for (int i0 = 0; i0 < 8; i0++)
	{
		tempH[i0] = tempH[i0] ^ tempN[i0];
		tempN[i0] = tempH[i0];
	}
	for (int i = 0; i < 8; i++)
	{
		for (int i0 = 0; i0 < 4; i0++)
		{
			value[i * 4 + i0] = (uint8_t)((tempH[i] >> (24 - i0 * 8)) & 0xFF);
		}
	}
}

#define NAMESPACE(name) dog_torch__crypto__hash__SM3_##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

SERIALIZE(BinaryData)* NAMESPACE(binary)(const LVALUE(SERIALIZE(BinaryData)) data)
{
	BinaryData data_ = data == nullptr ? BinaryData() : *data;
	using dog_torch::crypto::hash::algorithm::SM3;
	SM3 alg = SM3();
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

SERIALIZE(BinaryData)* NAMESPACE(file)(LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(UTILS(CppString)) path)
{
	using namespace dog_torch::utils;
	using dog_torch::crypto::hash::algorithm::SM3;
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
	SM3 alg = SM3();
	auto update_func = alg.get_update();
	auto trims_func = alg.get_trims();
	uint64_t pos = 0;
	BinaryData* hash_value = new BinaryData(alg.init_data());
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