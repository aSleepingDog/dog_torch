#include "crypto/hash/algorithms/SHA2.h"

namespace NSROOT = dog_torch::crypto::hash::algorithm;
using dog_torch::serialize::BinaryData;
using dog_torch::serialize::from_hex;

using dog_torch::utils::from_c_str;

using dog_torch::utils::from_uint64;
using dog_torch::utils::array_to_view;


constexpr auto ERROR_WRONG_EFFECTIVE = from_c_str("SHA2: nosupport effective length");
constexpr auto ERROR_LARGE_DATA_SIZE = from_c_str("SHA2: data size is too large");
constexpr auto ERROR_256_WRONG_BLOCK_SIZE = from_c_str("SHA2:256/224: block size must be 64 bytes");
constexpr auto ERROR_512_WRONG_BLOCK_SIZE = from_c_str("SHA2:512/384: block size must be 128 bytes");
constexpr auto ERROR_INVALID_SIZE = from_c_str("SHA2: invalid size");

const uint32_t NSROOT::SHA2::k_256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
const std::array<uint8_t, 32> NSROOT::SHA2::IV_256 = from_hex("6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19");
const std::array<uint8_t, 32> NSROOT::SHA2::IV_224 = from_hex("C1059ED8367CD5073070DD17F70E5939FFC00B316858151164F98FA7BEFA4FA4");
uint32_t NSROOT::SHA2::tick4B(const BinaryData& data, uint64_t size, uint64_t index)
{
	return (uint32_t)
		(data[size - index * 4 + 0] << 24) |
		(data[size - index * 4 + 1] << 16) | 
		(data[size - index * 4 + 2] << 8)  |
		(data[size - index * 4 + 3] << 0);
}
uint32_t NSROOT::SHA2::f1_64(uint32_t e, uint32_t f, uint32_t g, uint32_t h, const BinaryData& block, uint64_t size, uint64_t n)
{
	using namespace dog_torch::math::integer;
	uint32_t S1 = uirotr(e, 6) ^ uirotr(e, 11) ^ uirotr(e, 25);
	//printf("%0x\n", S1);
	uint32_t ch = (e & f) ^ ((~e) & g);
	uint32_t k = k_256[n];
	uint32_t w = tick4B(block, size, (64 - n));
	//printf("%0x\n", w);
	return h + S1 + ch + k + w;
}
uint32_t NSROOT::SHA2::f2_64(uint32_t a, uint32_t b, uint32_t c)
{
	using namespace dog_torch::math::integer;
	uint32_t S0 = uirotr(a, 2) ^ uirotr(a, 13) ^ uirotr(a, 22);
	uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
	return S0 + maj;
}
void NSROOT::SHA2::single_256_update(const BinaryData& block_, BinaryData& value)
{
	using namespace dog_torch::math::integer;
	if (block_.size() != 64)
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_256_WRONG_BLOCK_SIZE));
	}
	auto block = block_;
	uint32_t tempN[9], tempH[8];
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
	tempN[8] = 0;

	uint64_t size = block.size();
	while (size < 256)
	{
		uint32_t s0 = tick4B(block, size, 15);
		uint32_t s1 = tick4B(block, size, 2);
		uint32_t s2 = tick4B(block, size, 16);
		uint32_t s3 = tick4B(block, size, 7);
		s0 = uirotr(s0, 7) ^ uirotr(s0, 18) ^ (s0 >> 3);
		s1 = uirotr(s1, 17) ^ uirotr(s1, 19) ^ (s1 >> 10);
		uint32_t append = s0 + s1 + s2 + s3;
		for (int i0 = 0; i0 < 4; i0++)
		{
			block.push_back((uint8_t)(append << i0 * 8 >> 24));
		}
		size += 4;
	}
	for (int i0 = 0; i0 < 64; i0++)
	{
		uint32_t T1 = f1_64(tempN[4], tempN[5], tempN[6], tempN[7], block, size, i0);
		uint32_t T2 = f2_64(tempN[0], tempN[1], tempN[2]);
		tempN[3] += T1;
		tempN[7] = T1 + T2;
		for (int j = 8; j > 0; j--)
		{
			tempN[j] = tempN[j - 1];
		}
		tempN[0] = tempN[8];
	}
	for (int i1 = 0; i1 < 8; i1++)
	{
		tempH[i1] += tempN[i1];
		tempN[i1] = tempH[i1];
	}

	for (int i = 0; i < 8; i++)
	{
		for (int i0 = 0; i0 < 4; i0++)
		{
			value[i * 4 + i0] = (uint8_t)((tempH[i] >> (24 - i0 * 8)) & 0xFF);
		}
	}
}

const uint64_t NSROOT::SHA2::k_512[80] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817 };
const std::array<uint8_t, 64> NSROOT::SHA2::IV_512 = from_hex("6A09E667F3BCC908BB67AE8584CAA73B3C6EF372FE94F82BA54FF53A5F1D36F1510E527FADE682D19B05688C2B3E6C1F1F83D9ABFB41BD6B5BE0CD19137E2179");
const std::array<uint8_t, 64> NSROOT::SHA2::IV_384 = from_hex("CBBB9D5DC1059ED8629A292A367CD5079159015A3070DD17152FECD8F70E593967332667FFC00B318EB44A8768581511DB0C2E0D64F98FA747B5481DBEFA4FA4");
uint64_t NSROOT::SHA2::tick8B(const BinaryData & data, uint64_t size, uint64_t index)
{
	uint64_t res = 0;
	res |= ((uint64_t)data[size - index * 8 + 0] << (56 - 8 * 0));
	res |= ((uint64_t)data[size - index * 8 + 1] << (56 - 8 * 1));
	res |= ((uint64_t)data[size - index * 8 + 2] << (56 - 8 * 2));
	res |= ((uint64_t)data[size - index * 8 + 3] << (56 - 8 * 3));
	res |= ((uint64_t)data[size - index * 8 + 4] << (56 - 8 * 4));
	res |= ((uint64_t)data[size - index * 8 + 5] << (56 - 8 * 5));
	res |= ((uint64_t)data[size - index * 8 + 6] << (56 - 8 * 6));
	res |= ((uint64_t)data[size - index * 8 + 7] << (56 - 8 * 7));
	return res;
}
uint64_t NSROOT::SHA2::f1_128(uint64_t e, uint64_t f, uint64_t g, uint64_t h, const BinaryData& block, uint64_t size, uint64_t n)
{
	using namespace dog_torch::math::integer;
	uint64_t S1 = uirotr(e, 14) ^ uirotr(e, 18) ^ uirotr(e, 41);
	uint64_t ch = (e & f) ^ ((~e) & g);
	uint64_t temp = h + S1 + ch + k_512[n] + tick8B(block, size, (80 - n));
	return temp;
}
uint64_t NSROOT::SHA2::f2_128(uint64_t a, uint64_t b, uint64_t c)
{
	using namespace dog_torch::math::integer;
	uint64_t S0 = uirotr(a, 28) ^ uirotr(a, 34) ^ uirotr(a, 39);
	uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
	return S0 + maj;
}
void NSROOT::SHA2::single_512_update(const BinaryData& block_, BinaryData& value)
{
	using namespace dog_torch::math::integer;
	if (block_.size() != 128)
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_512_WRONG_BLOCK_SIZE));
	}
	uint64_t tempN[9], tempH[8];
	for (int i = 0; i < 8; i++)
	{
		uint64_t tempInt = 0;
		tempInt |= (uint64_t)value[i * 8] << 56;
		tempInt |= (uint64_t)value[i * 8 + 1] << 48;
		tempInt |= (uint64_t)value[i * 8 + 2] << 40;
		tempInt |= (uint64_t)value[i * 8 + 3] << 32;
		tempInt |= (uint64_t)value[i * 8 + 4] << 24;
		tempInt |= (uint64_t)value[i * 8 + 5] << 16;
		tempInt |= (uint64_t)value[i * 8 + 6] << 8;
		tempInt |= (uint64_t)value[i * 8 + 7];
		tempN[i] = tempInt;
		tempH[i] = tempInt;
	}
	tempN[8] = 0;
	auto block = block_;
	uint64_t size = block.size();
	while (size < 640)
	{
		uint64_t s0 = tick8B(block, size, 15);
		uint64_t s1 = tick8B(block, size, 2);
		uint64_t s2 = tick8B(block, size, 16);
		uint64_t s3 = tick8B(block, size, 7);
		s0 = uirotr(s0, 1) ^ uirotr(s0, 8) ^ (s0 >> 7);
		s1 = uirotr(s1, 19) ^ uirotr(s1, 61) ^ (s1 >> 6);
		uint64_t append = s0 + s1 + s2 + s3;
		for (int i0 = 0; i0 < 8; i0++)
		{
			block.push_back((uint8_t)(append << i0 * 8 >> 56));
		}
		size += 8;
	}
	for (int i0 = 0; i0 < 80; i0++)
	{
		uint64_t T1 = f1_128(tempN[4], tempN[5], tempN[6], tempN[7], block, size, i0);
		uint64_t T2 = f2_128(tempN[0], tempN[1], tempN[2]);
		tempN[3] += T1;
		tempN[7] = T1 + T2;
		for (int j = 8; j > 0; j--)
		{
			tempN[j] = tempN[j - 1];
		}
		tempN[0] = tempN[8];
	}
	for (int i1 = 0; i1 < 8; i1++)
	{
		tempH[i1] += tempN[i1];
		tempN[i1] = tempH[i1];
	}
	for (int i = 0; i < 8; i++)
	{
		for (int i0 = 0; i0 < 8; i0++)
		{
			value[i * 8 + i0] = (uint8_t)((tempH[i] >> (56 - i0 * 8)) & 0xFF);
		}
	}
}

uint64_t NSROOT::SHA2::max()
{
	return UINT64_MAX >> 3;
}

const NSROOT::Config& NSROOT::SHA2::allowed_config()
{
	static auto config = Config("SHA2", "28,32|48,64", {});
	return config;
}

NSROOT::SHA2::SHA2(uint64_t effective) : Algorithm(effective)
{
	if (effective != 28 && effective != 32 && effective != 48 && effective != 64)
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_INVALID_SIZE));
	}
}

NSROOT::SHA2::SHA2(const SHA2& sha2) : Algorithm(sha2)
{
	this->is_padding_80_ = sha2.is_padding_80_;
	this->is_padding_num_ = sha2.is_padding_num_;
}
NSROOT::SHA2& NSROOT::SHA2::operator=(const SHA2 & sha2)
{
	Algorithm::operator=(sha2);
	this->is_padding_80_ = sha2.is_padding_80_;
	this->is_padding_num_ = sha2.is_padding_num_;
	return *this;
}

NSROOT::SHA2::SHA2(SHA2&& sha2) noexcept : Algorithm(std::move(sha2))
{
	this->is_padding_80_ = sha2.is_padding_80_;
	this->is_padding_num_ = sha2.is_padding_num_;
}
NSROOT::SHA2& NSROOT::SHA2::operator=(SHA2&& sha2) noexcept
{
	if (this == &sha2) return *this;
	Algorithm::operator=(std::move(sha2));
	this->is_padding_80_ = sha2.is_padding_80_;
	this->is_padding_num_ = sha2.is_padding_num_;
	return *this;
}

NSROOT::Config NSROOT::SHA2::config() const
{
	return SHA2::allowed_config();
}
std::string NSROOT::SHA2::fmt_string() const
{
	return std::format("{}({})", this->config().name, this->effective * 8);
}
void NSROOT::SHA2::init()
{
	this->is_padding_80_ = false;
	this->is_padding_num_ = false;
}
BinaryData NSROOT::SHA2::init_data() const
{
	switch (this->effective)
	{
	case 28:
		return IV_224;
	case 32:
		return IV_256;
	case 48:
		return IV_384;
	case 64:
		return IV_512;
	default:
		throw DOG_EXCEPTION(array_to_view(ERROR_WRONG_EFFECTIVE));
	}
}

NSROOT::update_func NSROOT::SHA2::get_update() const
{
	switch (this->effective)
	{
	case 28:
	case 32:
		return single_256_update;
	case 48:
	case 64:
		return single_512_update;
	default:
		throw DOG_EXCEPTION(array_to_view(ERROR_WRONG_EFFECTIVE));
	}
}
NSROOT::trims_func NSROOT::SHA2::get_trims() const
{
	switch (this->effective)
	{
	case 32:
	case 64:
	{
		return [](BinaryData& value) -> void {};
	}
	case 28:
	{
		return [](BinaryData& value) -> void
			{
				value.resize(28);
			};
	}
	case 48:
	{
		return [](BinaryData& value) -> void
			{
				value.resize(32);
			};
	}
	default:
		throw DOG_EXCEPTION(array_to_view(ERROR_WRONG_EFFECTIVE));
	}
}
uint64_t NSROOT::SHA2::get_block_size() const
{
	switch (this->effective)
	{
	case 28:
	case 32:
		return 64;
	case 48:
	case 64:
		return 128;
	default:
		throw DOG_EXCEPTION(array_to_view(ERROR_WRONG_EFFECTIVE));
	}
}

uint64_t NSROOT::SHA2::get_out_size() const
{
	return this->effective;
}
std::unique_ptr<NSROOT::Algorithm> NSROOT::SHA2::clone() const
{
	return std::make_unique<SHA2>(*this);
}

bool NSROOT::SHA2::have_next_block(uint64_t data_pos, uint64_t data_total)
{
	if (data_total > this->max())
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_LARGE_DATA_SIZE));
	}
	if (this->effective == 32 || this->effective == 28)
	{
		auto dur = (data_total - data_pos);
		return dur >= 64 ? true : !this->is_padding_num_;
	}
	else if (this->effective == 64 || this->effective == 48)
	{
		auto dur = (data_total - data_pos);
		return dur >= 128 ? true : !this->is_padding_num_;
	}
	else
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_WRONG_EFFECTIVE));
	}
}
BinaryData NSROOT::SHA2::next_block(const BinaryData& data, uint64_t start, uint64_t& data_pos, uint64_t data_total)
{
	if (data_total > this->max())
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_LARGE_DATA_SIZE));
	}
	if (this->effective == 32 || this->effective == 28)
	{
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
	else if (this->effective == 64 || this->effective == 48)
	{
		auto res = data.sub_bytes_len(start, 128);
		data_pos += res.size();
		if (res.size() >= 128) return res;
		else
		{
			if (!this->is_padding_80_)
			{
				res.push_back(0x80);
				this->is_padding_80_ = true;
			}
			if (res.size() > (128 - 16))
			{
				while (res.size() < 128) res.push_back(0x00);
				return res;
			}
			else
			{
				using namespace dog_torch::math::integer;
				while (res.size() < (128 - 8)) res.push_back(0x00);
				uint64_t num = data_total << 3;
				this->is_padding_num_ = true;
				for (uint64_t i = 0; i < 8; i++)
					res.push_back(pick_byte(num, static_cast<uint8_t>(7 - i)));
				return res;
			}
		}

	}
	else
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_INVALID_SIZE));
	}
}
BinaryData NSROOT::SHA2::next_block(std::istream& data, uint64_t& data_pos, uint64_t data_total)
{
	if (data_total > this->max())
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_LARGE_DATA_SIZE));
	}
	if (this->effective == 32 || this->effective == 28)
	{
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
	else if (this->effective == 64 || this->effective == 48)
	{
		BinaryData res(64);
		data.read((char*)res.data_ptr(), 64);
		for (uint64_t i = data.gcount(); i < 64; i++) res.pop_back();
		data_pos += data.gcount();
		if (res.size() >= 128) return res;
		else
		{
			if (!this->is_padding_80_)
			{
				res.push_back(0x80);
				this->is_padding_80_ = true;
			}
			if (res.size() > (128 - 16))
			{
				while (res.size() < 128) res.push_back(0x00);
				return res;
			}
			else
			{
				using namespace dog_torch::math::integer; 
				while (res.size() < (128 - 8)) res.push_back(0x00);
				uint64_t num = data_total << 3;
				this->is_padding_num_ = true;
				for (uint64_t i = 0; i < 8; i++)
					res.push_back(pick_byte(num, static_cast<uint8_t>(7 - i)));
				return res;
			}
		}

	}
	else
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_WRONG_EFFECTIVE));
	}
}

#define NAMESPACE(name) dog_torch__crypto__hash__SHA2_##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

SERIALIZE(BinaryData)* NAMESPACE(256_binary)(const LVALUE(SERIALIZE(BinaryData)) data)
{
	BinaryData data_ = data == nullptr ? BinaryData() : *data;
	using dog_torch::crypto::hash::algorithm::SHA2;
	SHA2 alg = SHA2(32);
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
SERIALIZE(BinaryData)* NAMESPACE(224_binary)(const LVALUE(SERIALIZE(BinaryData)) data)
{
	BinaryData data_ = data == nullptr ? BinaryData() : *data;
	using dog_torch::crypto::hash::algorithm::SHA2;
	SHA2 alg = SHA2(28);
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
SERIALIZE(BinaryData)* NAMESPACE(384_binary)(const LVALUE(SERIALIZE(BinaryData)) data)
{
	BinaryData data_ = data == nullptr ? BinaryData() : *data;
	using dog_torch::crypto::hash::algorithm::SHA2;
	SHA2 alg = SHA2(48);
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
SERIALIZE(BinaryData)* NAMESPACE(512_binary)(const LVALUE(SERIALIZE(BinaryData)) data)
{
	BinaryData data_ = data == nullptr ? BinaryData() : *data;
	using dog_torch::crypto::hash::algorithm::SHA2;
	SHA2 alg = SHA2(64);
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

SERIALIZE(BinaryData)* NAMESPACE(256_file) (LVALUE(UTILS(CppResultSet))result_set, const LVALUE(UTILS(CppString))path)
{
	using namespace dog_torch::utils;
	using dog_torch::crypto::hash::algorithm::SHA2;
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
	SHA2 alg = SHA2(32);
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

SERIALIZE(BinaryData)* NAMESPACE(224_file) (LVALUE(UTILS(CppResultSet))result_set, const LVALUE(UTILS(CppString))path)
{
	using namespace dog_torch::utils;
	using dog_torch::crypto::hash::algorithm::SHA2;
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
	SHA2 alg = SHA2(24);
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

SERIALIZE(BinaryData)* NAMESPACE(384_file) (LVALUE(UTILS(CppResultSet))result_set, const LVALUE(UTILS(CppString))path)
{
	using namespace dog_torch::utils;
	using dog_torch::crypto::hash::algorithm::SHA2;
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
	SHA2 alg = SHA2(48);
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

SERIALIZE(BinaryData)* NAMESPACE(512_file) (LVALUE(UTILS(CppResultSet))result_set, const LVALUE(UTILS(CppString))path)
{
	using namespace dog_torch::utils;
	using dog_torch::crypto::hash::algorithm::SHA2;
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
	SHA2 alg = SHA2(64);
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

