#include "crypto/sym/block/modes/PCBC.h"

namespace NSROOT = dog_torch::crypto::sym::block::mode;
using dog_torch::serialize::BinaryData;
using Value = dog_torch::serialize::tlv::Value;
using dog_torch::utils::from_c_str;

using dog_torch::utils::from_uint64;
using dog_torch::utils::array_to_view;

constexpr auto ERROR_ALLOW_SIZE_OR_PADDING = from_c_str("PCBC: plain size must be multiple of block size when NoPadding");
constexpr auto ERROR_CRYPT_ALLOW_SIZE = from_c_str("PCBC: crypt size must be multiple of block size");

NSROOT::PCBC::PCBC(const BinaryData& iv, const padding::Padding& padding) : iv_(iv), Mode(padding) {};

NSROOT::PCBC::PCBC(const PCBC& other) : Mode(other)
{
	this->iv_ = other.iv_;
	this->padding_ = other.padding_->clone();
}
NSROOT::PCBC& NSROOT::PCBC::operator=(const PCBC& other)
{
	Mode::operator=(other);
	this->iv_ = other.iv_;
	this->padding_ = other.padding_->clone();
	return *this;
}
NSROOT::PCBC::PCBC(PCBC&& other) noexcept
{
	this->iv_ = std::move(other.iv_);
	this->padding_ = std::move(other.padding_);
}
NSROOT::PCBC& NSROOT::PCBC::operator=(PCBC&& other) noexcept
{
	if (this ==&other) return *this;
	Mode::operator=(std::move(other));
	this->iv_ = std::move(other.iv_);
	this->padding_ = std::move(other.padding_);
	return *this;
}

std::unique_ptr<NSROOT::Mode> NSROOT::PCBC::clone() const
{
	return std::make_unique<PCBC>(*this);
}
const NSROOT::Config& NSROOT::PCBC::params_config()
{
	static const Config config = Config("PCBC", {
		{"iv",ParamInfo(ParamType::Binary)},
		});
	return config;
}
NSROOT::Config NSROOT::PCBC::config() const
{
	return params_config();
}
std::string NSROOT::PCBC::fmt_string() const
{
	return std::format("PCBC<{}>", this->padding_->fmt_string());
}
Value NSROOT::PCBC::serialize() const
{
	using dog_torch::serialize::tlv::MIBString;
	auto total = static_cast<Mode>(*this).serialize();
	Value params = std::unordered_map<MIBString, Value>{};
	total.to_array()[0] = MIBString{ this->config().name };
	params.to_object()[MIBString{ "iv" }] = Value{ this->iv_.get_data() };
	total.to_array().push_back(params);
	return total;
}
bool NSROOT::PCBC::set_uint64_param(const std::string& param, uint64_t value)
{
	return false;
}
bool NSROOT::PCBC::set_string_param(const std::string& param, const std::string& value)
{
	return false;
}
bool NSROOT::PCBC::set_binary_param(const std::string& param, const BinaryData& value)
{
	if (param == "iv")
	{
		this->iv_ = value;
		return true;
	}
	return false;
}
bool NSROOT::PCBC::check(const algorithm::Algorithm& algorithm) const
{
	if (this->iv_.size() < algorithm.get_block_size())
	{
		return false;
	}
	return true;
}

NSROOT::crypt_func NSROOT::PCBC::get_mult_encrypt() const
{
	return [this](const BinaryData& p, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
		{
			return PCBC::encrypt(p, k, a, this->padding_->get_padding(), this->iv_);
		};
}
NSROOT::crypt_func NSROOT::PCBC::get_mult_decrypt() const
{
	return [this](const BinaryData& c, const BinaryData& k, const algorithm::Algorithm& a) -> BinaryData
		{
			return PCBC::decrypt(c, k, a, this->padding_->get_unpadding(), this->iv_);
		};
}

NSROOT::stream_crypt_func NSROOT::PCBC::get_stream_encrypt() const
{
	return [this](std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
		{
			return PCBC::encrypt_stream(p, t, c, k, a, this->padding_->get_padding(), this->iv_);
		};
}
NSROOT::stream_crypt_func NSROOT::PCBC::get_stream_decrypt() const
{
	return [this](std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
		{
			return PCBC::decrypt_stream(c, t, p, k, a, this->padding_->get_unpadding(), this->iv_);
		};
}

NSROOT::streamp_crypt_func NSROOT::PCBC::get_streamp_encrypt() const
{
	return [this](PauseableChannel& pc, std::istream& p, uint64_t t, std::ostream& c, const BinaryData& k, const algorithm::Algorithm& a)->void
		{
			return PCBC::encryptp_stream(pc, p, t, c, k, a, this->padding_->get_padding(), this->iv_);
		};
}
NSROOT::streamp_crypt_func NSROOT::PCBC::get_streamp_decrypt() const
{
	return [this](PauseableChannel& pc, std::istream& c, uint64_t t, std::ostream& p, const BinaryData& k, const algorithm::Algorithm& a)->void
		{
			return PCBC::decryptp_stream(pc, c, t, p, k, a, this->padding_->get_padding(), this->iv_);
		};
}

#define PCBC_INIT \
uint64_t block_size = algorithm.get_block_size(); \
uint64_t key_size = algorithm.get_key_size(); \
BinaryData iv_ = iv.sub_bytes_len(0,block_size);\
const BinaryData& key = available_key; \
using dog_torch::serialize::stream::read_bytes;

#define PCBC_EN_INIT \
PCBC_INIT \
algorithm::block_cryption_func block_encryption = algorithm.get_encrypt();\
algorithm::block_self_cryption_func block_self_encryption = algorithm.get_encrypt_self();

#define PCBC_DE_INIT \
PCBC_INIT \
algorithm::block_cryption_func block_decryption = algorithm.get_decrypt();\
algorithm::block_self_cryption_func block_self_decryption = algorithm.get_decrypt_self();

BinaryData NSROOT::PCBC::encrypt(
	const BinaryData& plain, 
	const BinaryData& available_key, 
	const algorithm::Algorithm& algorithm, padding::padding_func padding, const BinaryData& iv)
{
	PCBC_EN_INIT;

	BinaryData crypt;
	crypt.reserve(((1 + (plain.size() - 1) / block_size) * block_size));

	BinaryData buffer0, buffer1;
	padding(buffer0, block_size);
	if (plain.size() % block_size != 0 && buffer0.size() < block_size) 
		throw DOG_EXCEPTION(array_to_view(ERROR_ALLOW_SIZE_OR_PADDING));
	uint64_t now = 0;
	uint64_t num = 0;
	while (read_bytes(plain, plain.size(), now, buffer0, block_size, num) == block_size)
	{
		buffer1 = buffer0;
		buffer0 ^= iv_;
		block_self_encryption(buffer0, block_size, key, key_size);
		crypt += buffer0;
		iv_ = buffer1 ^ buffer0;
	}
	padding(buffer0, block_size);
	buffer0 ^= iv_;
	block_self_encryption(buffer0, block_size, key, key_size);
	crypt += buffer0;
	return crypt;

}

BinaryData NSROOT::PCBC::decrypt(
	const BinaryData& crypt, 
	const BinaryData& available_key, 
	const algorithm::Algorithm& algorithm, padding::padding_func unpadding, const BinaryData& iv)
{
	PCBC_DE_INIT;

	if (crypt.size() % block_size == 0) 
		throw DOG_EXCEPTION(array_to_view(ERROR_CRYPT_ALLOW_SIZE));
	BinaryData plain;
	plain.reserve(crypt.size());

	BinaryData buffer0, buffer1;
	uint64_t now = 0;
	uint64_t num = 0;
	while (read_bytes(crypt, crypt.size(), now, buffer0, block_size, num) == block_size&& now < crypt.size())
	{
		buffer1 = buffer0;
		block_self_decryption(buffer0, block_size, key, key_size);
		buffer0 ^= iv_;
		plain += buffer0;
		iv_ = buffer1 ^ buffer0;
	}
	block_self_decryption(buffer0, block_size, key, key_size);
	buffer0 ^= iv_;
	unpadding(buffer0, block_size);
	plain += buffer0;
	return plain;
}

void NSROOT::PCBC::encrypt_stream(
	std::istream& plain, uint64_t total, std::ostream& crypt, 
	const BinaryData& available_key, 
	const algorithm::Algorithm& algorithm, padding::padding_func padding, const BinaryData& iv)
{
	PCBC_EN_INIT;

	BinaryData buffer0, buffer1;
	padding(buffer0, block_size);
	if (total % block_size != 0 && buffer0.size() < block_size) 
		throw DOG_EXCEPTION(array_to_view(ERROR_ALLOW_SIZE_OR_PADDING));
	uint64_t now = 0;
	uint64_t num = 0;
	while (read_bytes(plain, total, now, buffer0, block_size, num) == block_size)
	{
		buffer1 = buffer0;
		buffer0 ^= iv_;
		block_self_encryption(buffer0, block_size, key, key_size);
		crypt.write(buffer0.data_stream(), buffer0.size());
		iv_ = buffer1 ^ buffer0;
	}
	padding(buffer0, block_size);
	buffer0 ^= iv_;
	block_self_encryption(buffer0, block_size, key, key_size);
	crypt.write(buffer0.data_stream(), buffer0.size());
	crypt.flush();
}

void NSROOT::PCBC::decrypt_stream(
	std::istream& crypt, uint64_t total, std::ostream& plain, 
	const BinaryData& available_key, 
	const algorithm::Algorithm& algorithm, padding::padding_func unpadding, const BinaryData& iv)
{
	PCBC_DE_INIT;
	if (total % block_size == 0) 
		throw DOG_EXCEPTION(array_to_view(ERROR_CRYPT_ALLOW_SIZE));
	BinaryData buffer0, buffer1;
	uint64_t now = 0;
	uint64_t num = 0;
	while (read_bytes(crypt, total, now, buffer0, block_size, num) == block_size&& now < total)
	{
		buffer1 = buffer0;
		block_self_decryption(buffer0, block_size, key, key_size);
		buffer0 ^= iv_;
		plain.write(buffer0.data_stream(), buffer0.size());
		iv_ = buffer1 ^ buffer0;
	}
	block_self_decryption(buffer0, block_size, key, key_size);
	buffer0 ^= iv_;
	unpadding(buffer0, block_size);
	plain.write(buffer0.data_stream(), buffer0.size());
	plain.flush();

}

void NSROOT::PCBC::encryptp_stream(
	PauseableChannel& pc, 
	std::istream& plain, uint64_t total, std::ostream& crypt, 
	const BinaryData& available_key, 
	const algorithm::Algorithm& algorithm, padding::padding_func padding, const BinaryData& iv)
{
	PCBC_EN_INIT;
	pc.start();
	BinaryData buffer0, buffer1;
	padding(buffer0, block_size);
	if (total % block_size != 0 && buffer0.size() < block_size) 
		throw DOG_EXCEPTION(array_to_view(ERROR_ALLOW_SIZE_OR_PADDING));
	uint64_t now = 0;
	uint64_t num = 0;
	while (read_bytes(plain, total, now, buffer0, block_size, num) == block_size)
	{
		if (pc.check_status()) break;
		buffer1 = buffer0;
		buffer0 ^= iv_;
		block_self_encryption(buffer0, block_size, key, key_size);
		crypt.write(buffer0.data_stream(), buffer0.size());
		iv_ = buffer1 ^ buffer0;
		pc.add_progress(block_size * 1.0 / total);
	}
	padding(buffer0, block_size);
	buffer0 ^= iv_;
	block_self_encryption(buffer0, block_size, key, key_size);
	crypt.write(buffer0.data_stream(), buffer0.size());
	crypt.flush();
	pc.set_progress(1.0);
	pc.stop();
}

void NSROOT::PCBC::decryptp_stream(
	PauseableChannel& pc, 
	std::istream& crypt, uint64_t total, std::ostream& plain, 
	const BinaryData& available_key, 
	const algorithm::Algorithm& algorithm, padding::padding_func unpadding, const BinaryData& iv)
{
	PCBC_DE_INIT;
	if (total % block_size == 0) 
		throw DOG_EXCEPTION(array_to_view(ERROR_CRYPT_ALLOW_SIZE));
	pc.start();
	BinaryData buffer0, buffer1;
	uint64_t now = 0;
	uint64_t num = 0;
	while (read_bytes(crypt, total, now, buffer0, block_size, num) == block_size&& now < total)
	{
		if (pc.check_status()) break;
		buffer1 = buffer0;
		block_self_decryption(buffer0, block_size, key, key_size);
		buffer0 ^= iv_;
		plain.write(buffer0.data_stream(), buffer0.size());
		iv_ = buffer1 ^ buffer0;
		pc.add_progress(block_size * 1.0 / total);
	}
	block_self_decryption(buffer0, block_size, key, key_size);
	buffer0 ^= iv_;
	unpadding(buffer0, block_size);
	plain.write(buffer0.data_stream(), buffer0.size());
	plain.flush();
	pc.set_progress(1.0);
	pc.stop();

}

#undef PCBC_DE_INIT
#undef PCBC_EN_INIT
#undef PCBC_INIT
