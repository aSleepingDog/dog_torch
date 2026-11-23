#include "crypto/asym/asym_base.h"
#include "error_msg.h"

namespace NSROOT = dog_torch::crypto::asym;
using BinaryData = dog_torch::serialize::BinaryData;

NSROOT::KeyPair::KeyPair(const BinaryData& public_key, const BinaryData& private_key)
	: public_key(public_key), private_key(private_key)
{}

NSROOT::algorithm::Config::Config(const std::string& name, const std::string& key_size_region, const std::map<std::string, ParamInfo>& params)
	: name(name), key_size_region(key_size_region), params(params)
{}

NSROOT::algorithm::Algorithm::~Algorithm() = default;

std::unique_ptr<NSROOT::algorithm::Algorithm> NSROOT::algorithm::Algorithm::clone() const
{
	return std::make_unique<NSROOT::algorithm::Algorithm>(*this);
}
NSROOT::algorithm::Algorithm::Algorithm(uint64_t key_size) : key_size(key_size) {};
NSROOT::algorithm::Config NSROOT::algorithm::Algorithm::get_config() const
{
	return Config("", "", {});
}
NSROOT::KeyPair NSROOT::algorithm::Algorithm::generate_key_pair() const
{
	return { BinaryData(), BinaryData() };
}

NSROOT::algorithm::crypt_func NSROOT::algorithm::Algorithm::get_encrypt_func() const
{
	return crypt_func();
}
NSROOT::algorithm::crypt_func NSROOT::algorithm::Algorithm::get_decrypt_func() const
{
	return crypt_func();
}
NSROOT::padding::Config::Config(const std::string& name, const std::map<std::string, ParamInfo>& params, std::map<std::string, PrimusType> primuses)
	: name(name), params(params), primuses(primuses) {};
NSROOT::padding::Padding::~Padding() = default;
NSROOT::padding::Config NSROOT::padding::Padding::get_config() const
{
	return Config("", {}, {});
}
bool NSROOT::padding::Padding::check(const algorithm::Algorithm& alg)
{
	return false;
}
std::unique_ptr<NSROOT::padding::Padding> NSROOT::padding::Padding::clone() const
{
	return nullptr;
}
NSROOT::padding::padding_func NSROOT::padding::Padding::get_padding() const
{
	return padding_func();
}
NSROOT::padding::padding_func NSROOT::padding::Padding::get_unpadding() const
{
	return padding_func();
}

const NSROOT::padding::Config& NSROOT::padding::NoPadding::get_allow_config()
{
	static const Config config = { "NoPadding",{} ,{} };
	return config;
}
NSROOT::padding::Config NSROOT::padding::NoPadding::get_config() const
{
	return NoPadding::get_allow_config();
}
std::unique_ptr<NSROOT::padding::Padding> NSROOT::padding::NoPadding::clone() const
{
	return std::make_unique<NSROOT::padding::NoPadding>(*this);
}
bool NSROOT::padding::NoPadding::check(const algorithm::Algorithm& alg)
{
	return true;
}
BinaryData NSROOT::padding::NoPadding::none(const BinaryData& data)
{
	return data;
}
NSROOT::padding::padding_func NSROOT::padding::NoPadding::get_padding() const
{
	return NoPadding::none;
}
NSROOT::padding::padding_func NSROOT::padding::NoPadding::get_unpadding() const
{
	return NoPadding::none;
}

NSROOT::Cipher::Cipher(const algorithm::Algorithm& alg, const padding::Padding& pad)
	: alg_p_(alg.clone()), pad_p_(pad.clone()) {};
NSROOT::Cipher::Cipher(const KeyPair& key_pair, const algorithm::Algorithm& alg, const padding::Padding& pad)
	: key_pair_(key_pair), alg_p_(alg.clone()), pad_p_(pad.clone()) {};

NSROOT::Cipher::Cipher(const Cipher& other)
	: key_pair_(other.key_pair_)
{
	this->alg_p_ = other.alg_p_->clone();
	this->pad_p_ = other.pad_p_->clone();
}
NSROOT::Cipher& NSROOT::Cipher::operator=(const Cipher& other)
{
	if (this == &other) return *this;
	this->alg_p_ = other.alg_p_->clone();
	this->pad_p_ = other.pad_p_->clone();
	this->key_pair_ = other.key_pair_;
	return *this;
}
NSROOT::Cipher::Cipher(Cipher&& other) noexcept
	: key_pair_(std::move(other.key_pair_))
{
	this->alg_p_ = std::move(other.alg_p_);
	this->pad_p_ = std::move(other.pad_p_);
}
NSROOT::Cipher& NSROOT::Cipher::operator=(Cipher&& other) noexcept
{
	if (this == &other) return *this;
	this->alg_p_ = std::move(other.alg_p_);
	this->pad_p_ = std::move(other.pad_p_);
	this->key_pair_ = std::move(other.key_pair_);
	return *this;
}

void NSROOT::Cipher::init()
{
	this->is_effective_ = this->pad_p_->check(*this->alg_p_);
}
bool NSROOT::Cipher::effective() const
{
	return this->is_effective_;
}
void NSROOT::Cipher::set_key(const KeyPair& key_pair)
{
	this->key_pair_ = key_pair;
}
void NSROOT::Cipher::init_key()
{
	this->key_pair_ = this->alg_p_->generate_key_pair();
}
NSROOT::KeyPair NSROOT::Cipher::key_pair() const
{
	return this->key_pair_;
}

BinaryData NSROOT::Cipher::encrypt(const BinaryData& plain)
{
	auto plain_ = this->pad_p_->get_padding()(plain);
	return this->alg_p_->get_encrypt_func()(plain_, this->key_pair_.public_key);
}
BinaryData NSROOT::Cipher::decrypt(const BinaryData& crypt)
{
	auto crypt_ = this->alg_p_->get_decrypt_func()(crypt, this->key_pair_.private_key);
	return this->pad_p_->get_unpadding()(crypt_);
}