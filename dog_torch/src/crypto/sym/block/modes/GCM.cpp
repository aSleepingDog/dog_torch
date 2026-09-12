#include "crypto/sym/block/modes/GCM.h"

namespace NSROOT = dog_torch::crypto::sym::block::mode;
using dog_torch::serialize::BinaryData;
using dog_torch::serialize::tlv::Value;
using dog_torch::utils::from_c_str;

using dog_torch::utils::from_uint64;
using dog_torch::utils::array_to_view;

constexpr auto ERROR_TAG_WRONG = from_c_str("GCM: tag is wrong because of wrong key or plain");

NSROOT::GCM::GCM(const BinaryData& iv, uint64_t shift, const padding::Padding& padding, const BinaryData& a, uint64_t tag_out)
	: Mode(padding), shift_(shift), tag_out_(tag_out), iv_(iv), aad_(a)
{
	this->tag_out_ = this->tag_out_ == 0 || this->tag_out_ > 16 ? 16 : this->tag_out_;
}
NSROOT::GCM::GCM(const GCM& other) : Mode(other)
{
	iv_ = other.iv_;
	shift_ = other.shift_;
	tag_out_ = other.tag_out_;
	aad_ = other.aad_;
}
NSROOT::GCM& NSROOT::GCM::operator=(const GCM& other)
{
	Mode::operator=(other);
	iv_ = other.iv_;
	shift_ = other.shift_;
	tag_out_ = other.tag_out_;
	aad_ = other.aad_;
	return *this;
}
NSROOT::GCM::GCM(GCM&& other) noexcept : Mode(std::move(other))
{
	iv_ = std::move(other.iv_);
	shift_ = other.shift_;
	tag_out_ = other.tag_out_;
	aad_ = std::move(other.aad_);
}
NSROOT::GCM& NSROOT::GCM::operator=(GCM&& other) noexcept
{
	if (this == &other) return *this;
	Mode::operator=(std::move(other));
	iv_ = std::move(other.iv_);
	shift_ = other.shift_;
	tag_out_ = other.tag_out_;
	aad_ = std::move(other.aad_);
	return *this;
}

std::unique_ptr<NSROOT::Mode> NSROOT::GCM::clone() const
{
	return std::make_unique<GCM>(*this);
}
const NSROOT::Config& NSROOT::GCM::params_config()
{
	static const Config config = Config("GCM", {
		{"iv",ParamType::Binary},
		{"shift",ParamType::UInt64},
		{"tag_out",ParamType::UInt64},
		{"aad",ParamType::Binary},
		});
	return config;
}
NSROOT::Config NSROOT::GCM::config() const
{
	return GCM::params_config();
}
std::string NSROOT::GCM::fmt_string() const
{
	if (this->shift_ == 0)
	{
		if (this->padding_->fmt_string() != "NoPadding")
		{
			return std::format("GCM<{}B,{}>", this->tag_out_, this->padding_->fmt_string());
		}
		else
		{
			return std::format("GCM<{}B>", this->tag_out_);
		}
	}
	else
	{
		if (this->padding_->fmt_string() != "NoPadding")
		{
			return std::format("GCM<{}B,{}B,{}>", this->tag_out_, this->shift_, this->padding_->fmt_string());
		}
		else
		{
			return std::format("GCM<{}B,{}B>", this->tag_out_, this->shift_);
		}
	}
}
Value NSROOT::GCM::serialize() const
{
	using dog_torch::serialize::tlv::MIBString;
	using dog_torch::math::number::Integer64;
	Value total = static_cast<Mode>(*this).serialize();
	total.to_array()[0] = MIBString{ this->config().name };
	Value params = std::unordered_map<MIBString, Value>{};
	total.to_array()[0] = MIBString{ this->config().name };
	params.to_object()[MIBString{ "shift" }] = Value{ Integer64{this->shift_} };
	params.to_object()[MIBString{ "tag_out" }] = Value{ Integer64{this->tag_out_} };
	params.to_object()[MIBString{ "aad" }] = Value{ this->aad_.get_data() };
	params.to_object()[MIBString{ "iv" }] = Value{ this->iv_.get_data() };
	total.to_array().push_back(params);
	return total;
}
bool NSROOT::GCM::set_uint64_param(const std::string& param, uint64_t value)
{
	return false;
}
bool NSROOT::GCM::set_string_param(const std::string& param, const std::string& value)
{
	return false;
}
bool NSROOT::GCM::set_binary_param(const std::string& param, const BinaryData& value)
{
	return false;
}
bool NSROOT::GCM::check(const algorithm::Algorithm& algorithm) const
{
	return algorithm.get_block_size() == 16;
}

NSROOT::crypt_func NSROOT::GCM::get_mult_encrypt() const
{
	return [this](const BinaryData& p, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
		{
			return GCM::encrypt(p, k, a, this->padding_->get_padding(), this->iv_, this->shift_, this->aad_, this->tag_out_);
		};
}
NSROOT::crypt_func NSROOT::GCM::get_mult_decrypt() const
{
	return [this](const BinaryData& c, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
		{
			return GCM::decrypt(c, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_, this->aad_, this->tag_out_);
		};
}

NSROOT::stream_crypt_func NSROOT::GCM::get_stream_encrypt() const
{
	return [this](std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
		{
			return GCM::encrypt_stream(p, t, c, k, a, this->padding_->get_padding(), this->iv_, this->shift_, this->aad_, this->tag_out_);
		};
}
NSROOT::stream_crypt_func NSROOT::GCM::get_stream_decrypt() const
{
	return [this](std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
		{
			return GCM::decrypt_stream(c, t, p, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_, this->aad_, this->tag_out_);
		};
}

NSROOT::streamp_crypt_func NSROOT::GCM::get_streamp_encrypt() const
{
	return[this](PauseableChannel& pc, std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
		{
			return GCM::encryptp_stream(pc, p, t, c, k, a, this->padding_->get_padding(), this->iv_, this->shift_, this->aad_, this->tag_out_);
		};
}
NSROOT::streamp_crypt_func NSROOT::GCM::get_streamp_decrypt() const
{
	return[this](PauseableChannel& pc, std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
		{
			return GCM::decryptp_stream(pc, c, t, p, k, a, this->padding_->get_unpadding(), this->iv_, this->shift_, this->aad_, this->tag_out_);
		};
}

void NSROOT::GCM::incr(BinaryData& conter, uint64_t s_bit)
{
	if (conter.size() == 0 || s_bit == 0) return;
	s_bit = s_bit > 64 ? 64 : s_bit;
	s_bit = ((s_bit % 8) && (conter.size() - 1 > s_bit / 8)) || (!(s_bit % 8) && (conter.size() > s_bit / 8)) ?
		s_bit : conter.size() * 8;
	uint64_t byte_size = s_bit / 8;
	if (s_bit % 8 > 0) byte_size++;
	uint64_t n = 0;
	uint64_t mask = (std::numeric_limits<uint64_t>::max() >> (64 - s_bit));
	memcpy(((uint8_t*)&n) + (8 - byte_size), conter.data_ptr() + (conter.size() - byte_size), byte_size);
	if constexpr (std::endian::native == std::endian::little)
	{
		n = std::byteswap(n);
	}
	n = (n + 1) & mask | (n & ~mask);
	if constexpr (std::endian::native == std::endian::little)
	{
		n = std::byteswap(n);
	}
	memcpy(conter.data_ptr() + (conter.size() - byte_size), ((uint8_t*)&n) + (8 - byte_size), byte_size);
}
using UInt128 = dog_torch::math::number::UnsignedInteger128;
UInt128 NSROOT::GCM::mult(const UInt128& x, const UInt128& y)
{
	UInt128 z = 0, v = y;
	for (uint64_t i = 0; i < 64; ++i)
	{
		const uint64_t& high = x.high();
		if (high >> (63 - i) & 1)
		{
			z ^= v;
		}
		if (v.low() & 0x01)
		{
			v >>= 1;
			v.high() ^= 0xE100000000000000;
		}
		else
		{
			v >>= 1;
		}
	}
	for (uint64_t i = 0; i < 64; ++i)
	{
		const uint64_t& low = x.low();
		if (low >> (63 - i) & 1)
		{
			z ^= v;
		}
		if (v.low() & 0x01)
		{
			v >>= 1;
			v.high() ^= 0xE100000000000000;
		}
		else
		{
			v >>= 1;
		}
	}
	return z;
}
UInt128 NSROOT::GCM::mult(const UInt128& b, const std::vector<std::array<UInt128, 16>>& table)
{
	UInt128 result = 0;
	for (uint8_t i = 0; i < 16; i += 2)
	{
		uint8_t n0 = static_cast<uint8_t>(b.low() >> (i * 4)) & 0xF;
		uint8_t n1 = static_cast<uint8_t>(b.low() >> (i * 4) >> 4) & 0xF;
		uint8_t n2 = static_cast<uint8_t>(b.high() >> (i * 4)) & 0xF;
		uint8_t n3 = static_cast<uint8_t>(b.high() >> (i * 4) >> 4) & 0xF;
		//std::cout << print(table[i][n0]) << " " << print(table[i + 1][n1]) << " " << print(table[i + 16][n2]) << " " << print(table[i + 17][n3]) << std::endl;
		result ^= table[i][n0] ^ table[i + 1][n1] ^ table[i + 16][n2] ^ table[i + 17][n3];
	}
	return result;
}
std::vector<std::array<UInt128, 16>> NSROOT::GCM::mult_table(const UInt128& a)
{
	std::vector<std::array<UInt128, 16>> result(32);
	using dog_torch::crypto::sym::block::mode::GCM;
	for (uint16_t j = 0; j < 16; ++j)
	{
		UInt128 n = j;
		for (uint16_t i = 0; i < 32; ++i)
		{
			result[i][j] = GCM::mult(a, n);
			n <<= 4;
		}
	}
	return result;
}
UInt128 NSROOT::GCM::tran_u128(std::vector<uint8_t>::const_iterator start, std::vector<uint8_t>::const_iterator end)
{
	if (end - start > 16)
	{
		end = start + 16;
	}
	UInt128 n_;
	uint8_t i = 0;
	auto it = start;
	for (; it != end && i < 8; ++it, ++i)
	{
		n_.high() <<= 8;
		n_.high() |= *it;
	}
	for (; it != end && i < 16; ++it, ++i)
	{
		n_.low() <<= 8;
		n_.low() |= *it;
	}
	return n_;
}
BinaryData NSROOT::GCM::tran_bin(const UInt128& n)
{
	BinaryData n_{ 16 };
	memcpy(n_.data_ptr(), &n.high(), 8);
	memcpy(n_.data_ptr() + 8, &n.low(), 8);
	if constexpr (std::endian::native == std::endian::little)
	{
		std::reverse(n_.begin(), n_.begin() + 8);
		std::reverse(n_.begin() + 8, n_.end());
	}
	return n_;
}
BinaryData NSROOT::GCM::GHASH(const std::vector<std::array<UInt128, 16>>& t, const BinaryData& x)
{
	UInt128 y = 0;
	for (uint64_t i = 0; i < x.size(); i += 16)
	{
		UInt128 x_ = GCM::tran_u128(x.cbegin() + i, x.cbegin() + i + 16);
		y ^= x_;
		y = mult(y, t);
	}
	return GCM::tran_bin(y);
}
uint64_t NSROOT::GCM::fill_size(uint64_t l)
{
	return 16 * (l % 16 ? l / 16 + 1 : l / 16);
}

#define GCM_ININ \
uint64_t block_size = algorithm.get_block_size(); \
uint64_t key_size = algorithm.get_key_size();\
BinaryData iv_ = iv;\
shift = shift == 0 ? block_size : shift;\
const BinaryData& key = available_key;\
using dog_torch::serialize::stream::read_bytes;\
using dog_torch::serialize::stream::read_bits;\
using dog_torch::serialize::stream::write_bits;\
algorithm::block_cryption_func block_encryption = algorithm.get_encrypt();\
algorithm::block_self_cryption_func block_self_encryption = algorithm.get_encrypt_self();\
tag_out = tag_out == 0 || tag_out > 16 ? 16 : tag_out\

BinaryData NSROOT::GCM::encrypt(
	const BinaryData& plain,
	const BinaryData& available_key,
	const algorithm::Algorithm& algorithm, padding::padding_func padding,
	const BinaryData& iv, uint64_t shift, const BinaryData& acc, uint64_t tag_out
)
{
	GCM_ININ;

	BinaryData h_ = block_encryption(BinaryData{ block_size }, block_size, available_key, key_size);
	auto h = mult_table(tran_u128(h_.cbegin(), h_.cend()));
	if (iv_.size() == 12)
	{
		iv_.resize(iv_.size() + 4);
		iv_.back() = 0x01;
	}
	else
	{
		uint64_t s = iv_.size() * 8;
		iv_.resize(fill_size(iv_.size()) + 8);
		for (uint64_t i = 0; i < 8; ++i)
		{
			iv_.push_back(static_cast<uint8_t>(s >> (56 - i * 8)));
		}
		iv_ = GHASH(h, iv_);
	}
	BinaryData j0_crypto = block_encryption(iv_, block_size, available_key, key_size);
	BinaryData s = acc;
	s.resize(fill_size(s.size()));
	s = GHASH(h, s);

	BinaryData crypt;
	crypt.reserve(plain.size());

	BinaryData buffer0{ 16 }, buffer1;
	uint64_t now = 0, num = 0;
	while (read_bytes(plain, plain.size(), now, buffer0, shift, num) == shift)
	{

		incr(iv_, 32);
		buffer1 = block_encryption(iv_, block_size, key, key_size);
		buffer0 ^= buffer1;
		buffer0.resize(num);
		crypt += buffer0;
		buffer0.resize(16);
		s = GHASH(h, s ^ buffer0);
	}
	incr(iv_, 32);
	buffer1 = block_encryption(iv_, block_size, key, key_size);
	buffer0.resize(num);
	padding(buffer0, shift);
	buffer0 ^= buffer1.sub_bytes_len(0, buffer0.size());
	crypt += buffer0;
	if (buffer0.size())
	{
		buffer0.resize(16);
		s = GHASH(h, s ^ buffer0);
	}
	BinaryData len{ 16 };
	for (uint64_t i = 0; i < 8; ++i)
	{
		len[i] = static_cast<uint8_t>((acc.size() * 8) >> (56 - i * 8));
		len[i + 8] = static_cast<uint8_t>((crypt.size() * 8) >> (56 - i * 8));
	}
	s = GHASH(h, s ^ len);
	BinaryData tag = j0_crypto ^ s;
	//std::cout << tag.to_hex_string(true) << std::endl;
	return crypt + tag.sub_bytes_len(0, tag_out);
}
BinaryData NSROOT::GCM::decrypt(
	const BinaryData& crypt, 
	const BinaryData& available_key, 
	const algorithm::Algorithm& algorithm, padding::padding_func unpadding, 
	const BinaryData& iv, uint64_t shift, const BinaryData& acc, uint64_t tag_out
)
{
	GCM_ININ;

	BinaryData h_ = block_encryption(BinaryData{ block_size }, block_size, available_key, key_size);
	auto h = mult_table(tran_u128(h_.cbegin(), h_.cend()));
	if (iv_.size() == 12)
	{
		iv_.resize(iv_.size() + 4);
		iv_.back() = 0x01;
	}
	else
	{
		uint64_t s = iv_.size() * 8;
		iv_.resize(fill_size(iv_.size()) + 8);
		for (uint64_t i = 0; i < 8; ++i)
		{
			iv_.push_back(static_cast<uint8_t>(s >> (56 - i * 8)));
		}
		iv_ = GHASH(h, iv_);
	}
	BinaryData j0_crypto = block_encryption(iv_, block_size, available_key, key_size);
	BinaryData s = acc;
	s.resize(fill_size(s.size()));
	s = GHASH(h, s);

	uint64_t total = crypt.size() - tag_out;

	BinaryData plain;
	plain.reserve(total);

	BinaryData buffer0{ 16 }, buffer1;
	uint64_t now = 0, num = 0;
	while (read_bytes(crypt, total, now, buffer0, shift, num) == shift&& now < total)
	{
		buffer0.resize(num);
		buffer0.resize(16);
		s = GHASH(h, s ^ buffer0);
		incr(iv_, 32);
		buffer1 = block_encryption(iv_, block_size, key, key_size);
		buffer0 ^= buffer1;
		plain += buffer0.sub_bytes_len(0, shift);
	}
	incr(iv_, 32);
	buffer1 = block_encryption(iv_, block_size, key, key_size);
	buffer0.resize(num);
	buffer1.resize(num);
	buffer1 ^= buffer0;
	unpadding(buffer1, shift);
	plain += buffer1;
	if (buffer0.size())
	{
		buffer0.resize(16);
		s = GHASH(h, s ^ buffer0);
	}


	BinaryData len{ 16 };
	for (uint64_t i = 0; i < 8; ++i)
	{
		len[i] = static_cast<uint8_t>((acc.size() * 8) >> (56 - i * 8));
		len[i + 8] = static_cast<uint8_t>((total * 8) >> (56 - i * 8));
	}
	s = GHASH(h, s ^ len);
	BinaryData now_tag = j0_crypto ^ s;
	BinaryData ori_tag = crypt.sub_bytes_len(now, tag_out);
	//std::cout << now_tag.to_hex_string(true) << std::endl;
	//std::cout << ori_tag.to_hex_string(true) << std::endl;
	if (now_tag != ori_tag)
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_TAG_WRONG));
	}
	return plain;

}

void NSROOT::GCM::encrypt_stream(
	std::istream& plain, uint64_t total, std::ostream& crypt,
	const BinaryData& available_key,
	const algorithm::Algorithm& algorithm, padding::padding_func padding,
	const BinaryData& iv, uint64_t shift, const BinaryData& acc, uint64_t tag_out
)
{
	GCM_ININ;

	BinaryData h_ = block_encryption(BinaryData{ block_size }, block_size, available_key, key_size);
	auto h = mult_table(tran_u128(h_.cbegin(), h_.cend()));
	if (iv_.size() == 12)
	{
		iv_.resize(iv_.size() + 4);
		iv_.back() = 0x01;
	}
	else
	{
		uint64_t s = iv_.size() * 8;
		iv_.resize(fill_size(iv_.size()) + 8);
		for (uint64_t i = 0; i < 8; ++i)
		{
			iv_.push_back(static_cast<uint8_t>(s >> (56 - i * 8)));
		}
		iv_ = GHASH(h, iv_);
	}
	BinaryData j0_crypto = block_encryption(iv_, block_size, available_key, key_size);
	BinaryData s = acc;
	s.resize(fill_size(s.size()));
	s = GHASH(h, s);

	BinaryData buffer0{ 16 }, buffer1;
	uint64_t now = 0, num = 0;
	while (read_bytes(plain, total, now, buffer0, shift, num) == shift)
	{

		incr(iv_, 32);
		buffer1 = block_encryption(iv_, block_size, key, key_size);
		buffer0 ^= buffer1;
		buffer0.resize(num);
		crypt.write(buffer0.data_stream(), shift);
		buffer0.resize(16);
		s = GHASH(h, s ^ buffer0);
	}
	incr(iv_, 32);
	buffer1 = block_encryption(iv_, block_size, key, key_size);
	buffer0.resize(num);
	padding(buffer0, shift);
	buffer0 ^= buffer1.sub_bytes_len(0, buffer0.size());
	crypt.write(buffer0.data_stream(), buffer0.size());
	if (buffer0.size())
	{
		buffer0.resize(16);
		s = GHASH(h, s ^ buffer0);
	}
	BinaryData len{ 16 };
	for (uint64_t i = 0; i < 8; ++i)
	{
		len[i] = static_cast<uint8_t>((acc.size() * 8) >> (56 - i * 8));
		len[i + 8] = static_cast<uint8_t>((total * 8) >> (56 - i * 8));
	}
	s = GHASH(h, s ^ len);
	BinaryData tag = j0_crypto ^ s;
	tag.resize(tag_out);
	//std::cout << tag.to_hex_string(true) << std::endl;
	crypt.write(tag.data_stream(), tag_out);
	crypt.flush();
}
void NSROOT::GCM::decrypt_stream(
	std::istream& crypt, uint64_t total, std::ostream& plain,
	const BinaryData& available_key,
	const algorithm::Algorithm& algorithm, padding::padding_func unpadding,
	const BinaryData& iv, uint64_t shift, const BinaryData& acc, uint64_t tag_out
)
{
	GCM_ININ;

	BinaryData h_ = block_encryption(BinaryData{ block_size }, block_size, available_key, key_size);
	auto h = mult_table(tran_u128(h_.cbegin(), h_.cend()));
	if (iv_.size() == 12)
	{
		iv_.resize(iv_.size() + 4);
		iv_.back() = 0x01;
	}
	else
	{
		uint64_t s = iv_.size() * 8;
		iv_.resize(fill_size(iv_.size()) + 8);
		for (uint64_t i = 0; i < 8; ++i)
		{
			iv_.push_back(static_cast<uint8_t>(s >> (56 - i * 8)));
		}
		iv_ = GHASH(h, iv_);
	}
	BinaryData j0_crypto = block_encryption(iv_, block_size, available_key, key_size);
	BinaryData s = acc;
	s.resize(fill_size(s.size()));
	s = GHASH(h, s);

	total = total - tag_out;

	BinaryData buffer0{ 16 }, buffer1;
	uint64_t now = 0, num = 0;
	while (read_bytes(crypt, total, now, buffer0, shift, num) == shift&& now < total)
	{
		buffer0.resize(num);
		buffer0.resize(16);
		s = GHASH(h, s ^ buffer0);
		incr(iv_, 32);
		buffer1 = block_encryption(iv_, block_size, key, key_size);
		buffer0 ^= buffer1;
		plain.write(buffer0.data_stream(), shift);
	}
	incr(iv_, 32);
	buffer1 = block_encryption(iv_, block_size, key, key_size);
	buffer0.resize(num);
	buffer1.resize(num);
	buffer1 ^= buffer0;
	unpadding(buffer1, shift);
	plain.write(buffer1.data_stream(), buffer0.size());
	if (buffer0.size())
	{
		buffer0.resize(16);
		s = GHASH(h, s ^ buffer0);
	}


	BinaryData len{ 16 };
	for (uint64_t i = 0; i < 8; ++i)
	{
		len[i] = static_cast<uint8_t>((acc.size() * 8) >> (56 - i * 8));
		len[i + 8] = static_cast<uint8_t>((total * 8) >> (56 - i * 8));
	}
	s = GHASH(h, s ^ len);
	BinaryData now_tag = j0_crypto ^ s;
	BinaryData ori_tag{ tag_out };
	read_bytes(crypt, total + tag_out, now, ori_tag, shift, num);
	//std::cout << now_tag.to_hex_string(true) << std::endl;
	//std::cout << ori_tag.to_hex_string(true) << std::endl;
	if (now_tag != ori_tag)
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_TAG_WRONG));
	}
	plain.flush();
}

void NSROOT::GCM::encryptp_stream(
	PauseableChannel& pc,
	std::istream& plain, uint64_t total, std::ostream& crypt,
	const BinaryData& available_key,
	const algorithm::Algorithm& algorithm, padding::padding_func padding,
	const BinaryData& iv, uint64_t shift, const BinaryData& acc, uint64_t tag_out
)
{
	GCM_ININ;
	pc.start();
	BinaryData h_ = block_encryption(BinaryData{ block_size }, block_size, available_key, key_size);
	auto h = mult_table(tran_u128(h_.cbegin(), h_.cend()));
	if (iv_.size() == 12)
	{
		iv_.resize(iv_.size() + 4);
		iv_.back() = 0x01;
	}
	else
	{
		uint64_t s = iv_.size() * 8;
		iv_.resize(fill_size(iv_.size()) + 8);
		for (uint64_t i = 0; i < 8; ++i)
		{
			iv_.push_back(static_cast<uint8_t>(s >> (56 - i * 8)));
		}
		iv_ = GHASH(h, iv_);
	}
	BinaryData j0_crypto = block_encryption(iv_, block_size, available_key, key_size);
	BinaryData s = acc;
	s.resize(fill_size(s.size()));
	s = GHASH(h, s);

	BinaryData buffer0{ 16 }, buffer1;
	uint64_t now = 0, num = 0;
	while (read_bytes(plain, total, now, buffer0, shift, num) == shift)
	{

		if (pc.check_status()) break;
		incr(iv_, 32);
		buffer1 = block_encryption(iv_, block_size, key, key_size);
		buffer0 ^= buffer1;
		buffer0.resize(num);
		crypt.write(buffer0.data_stream(), shift);
		buffer0.resize(16);
		s = GHASH(h, s ^ buffer0);
		pc.add_progress(shift * 1.0 / (total * 8));
	}
	incr(iv_, 32);
	buffer1 = block_encryption(iv_, block_size, key, key_size);
	buffer0.resize(num);
	padding(buffer0, shift);
	buffer0 ^= buffer1.sub_bytes_len(0, buffer0.size());
	crypt.write(buffer0.data_stream(), buffer0.size());
	if (buffer0.size())
	{
		buffer0.resize(16);
		s = GHASH(h, s ^ buffer0);
	}
	BinaryData len{ 16 };
	for (uint64_t i = 0; i < 8; ++i)
	{
		len[i] = static_cast<uint8_t>((acc.size() * 8) >> (56 - i * 8));
		len[i + 8] = static_cast<uint8_t>((total * 8) >> (56 - i * 8));
	}
	s = GHASH(h, s ^ len);
	BinaryData tag = j0_crypto ^ s;
	tag.resize(tag_out);
	//std::cout << tag.to_hex_string(true) << std::endl;
	crypt.write(tag.data_stream(), tag_out);
	crypt.flush();    
	pc.set_progress(1.0);
	pc.stop();
}
void NSROOT::GCM::decryptp_stream(
	PauseableChannel& pc,
	std::istream& crypt, uint64_t total, std::ostream& plain,
	const BinaryData& available_key,
	const algorithm::Algorithm& algorithm, padding::padding_func unpadding,
	const BinaryData& iv, uint64_t shift, const BinaryData& acc, uint64_t tag_out
)
{
	GCM_ININ;
	pc.start();
	BinaryData h_ = block_encryption(BinaryData{ block_size }, block_size, available_key, key_size);
	auto h = mult_table(tran_u128(h_.cbegin(), h_.cend()));
	if (iv_.size() == 12)
	{
		iv_.resize(iv_.size() + 4);
		iv_.back() = 0x01;
	}
	else
	{
		uint64_t s = iv_.size() * 8;
		iv_.resize(fill_size(iv_.size()) + 8);
		for (uint64_t i = 0; i < 8; ++i)
		{
			iv_.push_back(static_cast<uint8_t>(s >> (56 - i * 8)));
		}
		iv_ = GHASH(h, iv_);
	}
	BinaryData j0_crypto = block_encryption(iv_, block_size, available_key, key_size);
	BinaryData s = acc;
	s.resize(fill_size(s.size()));
	s = GHASH(h, s);

	total = total - tag_out;

	BinaryData buffer0{ 16 }, buffer1;
	uint64_t now = 0, num = 0;
	while (read_bytes(crypt, total, now, buffer0, shift, num) == shift&& now < total)
	{
		if (pc.check_status()) break;
		buffer0.resize(num);
		buffer0.resize(16);
		s = GHASH(h, s ^ buffer0);
		incr(iv_, 32);
		buffer1 = block_encryption(iv_, block_size, key, key_size);
		buffer0 ^= buffer1;
		plain.write(buffer0.data_stream(), shift);
		pc.add_progress(shift * 1.0 / (total * 8));
	}
	incr(iv_, 32);
	buffer1 = block_encryption(iv_, block_size, key, key_size);
	buffer0.resize(num);
	buffer1.resize(num);
	buffer1 ^= buffer0;
	unpadding(buffer1, shift);
	plain.write(buffer1.data_stream(), buffer0.size());
	if (buffer0.size())
	{
		buffer0.resize(16);
		s = GHASH(h, s ^ buffer0);
	}


	BinaryData len{ 16 };
	for (uint64_t i = 0; i < 8; ++i)
	{
		len[i] = static_cast<uint8_t>((acc.size() * 8) >> (56 - i * 8));
		len[i + 8] = static_cast<uint8_t>((total * 8) >> (56 - i * 8));
	}
	s = GHASH(h, s ^ len);
	BinaryData now_tag = j0_crypto ^ s;
	BinaryData ori_tag{ tag_out };
	read_bytes(crypt, total + tag_out, now, ori_tag, shift, num);
	//std::cout << now_tag.to_hex_string(true) << std::endl;
	//std::cout << ori_tag.to_hex_string(true) << std::endl;
	if (now_tag != ori_tag&& pc.status() != dog_torch::async::Status::Stopped)
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_TAG_WRONG));
	}
	plain.flush();
	pc.set_progress(1.0);
	pc.stop();
}