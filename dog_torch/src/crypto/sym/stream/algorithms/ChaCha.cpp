#include "crypto/sym/stream/algorithms/ChaCha.h"

namespace NSROOT = dog_torch::crypto::sym::stream::algorithm;
using dog_torch::serialize::BinaryData;
using dog_torch::utils::from_c_str;
using dog_torch::utils::from_uint64;

using dog_torch::utils::array_to_view;

constexpr auto ERROR_UNSUPPORTED_ROUND = from_c_str("Unsupported ChaCha round");
constexpr auto ERROR_UNSUPPORTED_KEY_SIZE = from_c_str("Unsupported ChaCha round");

NSROOT::ChaCha::ChaCha(uint64_t round)
	: Algorithm(round, 40),count_(0)
{}

const NSROOT::Config& NSROOT::ChaCha::allowed_config()
{
	static Config config("ChaCha", "8,12,20", "40");
	return config;
}

void inline NSROOT::ChaCha::trans(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
	using dog_torch::math::integer::uirotl;
	using dog_torch::math::integer::uirotr;
	a += b; d ^= a; d = uirotl(d, 16);
	c += d; b ^= c; b = uirotl(b, 12);
	a += b; d ^= a; d = uirotl(d, 8);
	c += d; b ^= c; b = uirotl(b, 7);
}
BinaryData NSROOT::ChaCha::generate_stream(const BinaryData& key_nonce, uint64_t count, uint64_t round)
{
	using dog_torch::math::integer::pick_byte;
	BinaryData xor_stream = { "expand 32-byte k",BinaryData::Type::UTF8 };
	xor_stream.reserve(64);
	xor_stream += key_nonce;
	xor_stream.resize(64);
	for (uint8_t i = 0; i < 8; ++i)
	{
		xor_stream[56 + i] = (pick_byte(count, i));
		std::swap(xor_stream[56 + i], xor_stream[48 + i]);
	}
	//std::cout << xor_stream.to_hex_string(true) << std::endl;

	std::array<uint32_t, 16> s = { 0 };
	for (uint8_t i = 0; i < 16; ++i)
	{
		for (uint8_t j = 0; j < 4; ++j)
		{
			s[i] |= static_cast<uint32_t>(xor_stream[i * 4 + j]) << (j * 8);
		}
	}
	for (uint64_t i = 0; i < round / 2; ++i)
	{
		trans(s[0], s[4], s[8], s[12]);
		trans(s[1], s[5], s[9], s[13]);
		trans(s[2], s[6], s[10], s[14]);
		trans(s[3], s[7], s[11], s[15]);

		trans(s[0], s[5], s[10], s[15]);
		trans(s[1], s[6], s[11], s[12]);
		trans(s[2], s[7], s[8], s[13]);
		trans(s[3], s[4], s[9], s[14]);
	}

	for (uint8_t i = 0; i < 16; ++i)
	{
		uint32_t o = 0;
		for (uint8_t j = 0; j < 4; ++j)
		{
			o |= static_cast<uint32_t>(xor_stream[i * 4 + j]) << (j * 8);
		}
		o += s[i];
		for (uint8_t j = 0; j < 4; ++j)
		{
			xor_stream[i * 4 + j] = static_cast<uint8_t>(o >> (j * 8));
		}
	}
	return xor_stream;
}

NSROOT::Config NSROOT::ChaCha::config() const
{
	return ChaCha::allowed_config();
}

std::unique_ptr<NSROOT::Algorithm> NSROOT::ChaCha::clone() const
{
	return std::make_unique<ChaCha>(*this);
}

void NSROOT::ChaCha::init()
{
	this->count_ = 0;
}
std::string NSROOT::ChaCha::fmt_string() const
{
	return std::format("ChaCha({})", this->effective_);
}
uint64_t NSROOT::ChaCha::updata_size() const
{
	return 64;
}
NSROOT::UpdateFunc NSROOT::ChaCha::update_func()
{
	return [this](const BinaryData& key) -> BinaryData
		{
			return generate_stream(key, this->count_++, this->effective_);
		};
}