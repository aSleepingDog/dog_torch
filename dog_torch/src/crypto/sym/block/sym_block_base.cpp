#include "crypto/sym/block/sym_block_base.h"

namespace NSROOT = dog_torch::crypto::sym::block;
using BinaryData = dog_torch::serialize::BinaryData;
using Value = dog_torch::serialize::tlv::Value;
using Cipher = dog_torch::crypto::sym::Cipher;

using dog_torch::utils::from_c_str;
using dog_torch::utils::from_uint64;
using dog_torch::utils::array_to_view;

constexpr auto ERROR_SETTING_PADDING = from_c_str("padding must be set");
constexpr auto ERROR_SETTING_ALGORITHM_MODE = from_c_str("algorithm or mode must be set");
constexpr auto ERROR_NOT_COMPATIBLE = from_c_str("algorithm and mode are not compatible");

NSROOT::algorithm::Config::Config(const std::string& name, const std::string& block_size_region, const std::string& key_size_region)
	: name(name), block_size_region(block_size_region), key_size_region(key_size_region)
{}
NSROOT::algorithm::Config NSROOT::algorithm::Algorithm::config() const
{
	return Config("","","");
}
std::string NSROOT::algorithm::Algorithm::fmt_string() const
{
	return "";
}
std::unique_ptr<NSROOT::algorithm::Algorithm> NSROOT::algorithm::Algorithm::clone() const
{
	return std::make_unique<NSROOT::algorithm::Algorithm>(*this);
}
NSROOT::algorithm::Algorithm::Algorithm(uint64_t block_size, uint64_t key_size) : block_size_(block_size), key_size_(key_size) {}
NSROOT::algorithm::extend_key_func NSROOT::algorithm::Algorithm::get_extend_key() const
{
	return [](const BinaryData&, uint64_t, uint64_t) -> BinaryData {return BinaryData(); };
}
NSROOT::algorithm::block_cryption_func NSROOT::algorithm::Algorithm::get_encrypt() const
{
	return [](const BinaryData&, uint64_t, const BinaryData&, uint64_t) -> BinaryData {return BinaryData(); };
}
NSROOT::algorithm::block_cryption_func NSROOT::algorithm::Algorithm::get_decrypt() const
{
	return [](const BinaryData&, uint64_t, const BinaryData&, uint64_t) -> BinaryData {return BinaryData(); };
}
NSROOT::algorithm::block_self_cryption_func NSROOT::algorithm::Algorithm::get_encrypt_self() const
{
	return [](BinaryData&, uint64_t, const BinaryData&, uint64_t) {};
}
NSROOT::algorithm::block_self_cryption_func NSROOT::algorithm::Algorithm::get_decrypt_self() const
{
	return [](BinaryData&, uint64_t, const BinaryData&, uint64_t) {};
}

NSROOT::padding::Config::Config(const std::string& name, const std::string& block_size_region)
	: name(name), allowed_block_size_region(block_size_region) {}

NSROOT::padding::Config NSROOT::padding::Padding::config() const
{
	return Config("", "");
}
std::unique_ptr<NSROOT::padding::Padding> NSROOT::padding::Padding::clone() const
{
	return std::make_unique<Padding>(*this);
}
std::string NSROOT::padding::Padding::fmt_string() const
{
	return "";
}
Value NSROOT::padding::Padding::serialize() const
{
	if (this->config().name == "")
	{
		return nullptr;
	}
	using dog_torch::serialize::tlv::MIBString;
	return Value{ MIBString{this->config().name } };
}
bool NSROOT::padding::Padding::check(uint64_t block_size) const
{
	return true;
}
NSROOT::padding::padding_func NSROOT::padding::Padding::get_padding() const
{
	return padding_func();

}
NSROOT::padding::padding_func NSROOT::padding::Padding::get_unpadding() const
{
	return padding_func();
}

const NSROOT::padding::Config& NSROOT::padding::NoPadding::allowed_config()
{
	static const Config config = Config("NoPadding", "[1,18446744073709551615|1]");
	return config;
}
NSROOT::padding::Config NSROOT::padding::NoPadding::config() const
{
	return NoPadding::allowed_config();
}
std::unique_ptr<NSROOT::padding::Padding> NSROOT::padding::NoPadding::clone() const
{
	return std::make_unique<NoPadding>(*this);
}
std::string NSROOT::padding::NoPadding::fmt_string() const
{
	return "NoPadding";
}
Value dog_torch::crypto::sym::block::padding::NoPadding::serialize() const
{
	using dog_torch::serialize::tlv::MIBString;
	return Value(MIBString{ "NoPadding" });
}
bool NSROOT::padding::NoPadding::check(uint64_t block_size) const
{
	return true;
}
NSROOT::padding::padding_func NSROOT::padding::NoPadding::get_padding() const
{
	return [](BinaryData&, uint64_t)->void {};
}
NSROOT::padding::padding_func NSROOT::padding::NoPadding::get_unpadding() const
{
	return [](BinaryData&, uint64_t)->void {};
}

Value NSROOT::algorithm::Algorithm::serialize() const
{
	using dog_torch::serialize::tlv::MIBString;
	using dog_torch::math::number::Integer64;
	if (this->config().name == "")
	{
		return nullptr;
	}
	Value name = MIBString{ this->config().name };
	Value block_size = Integer64{ this->block_size_ };
	Value key_size = Integer64{ this->key_size_ };
	Value total = std::vector<Value>{};
	total.to_array().push_back(std::move(name));
	total.to_array().push_back(std::move(block_size));
	total.to_array().push_back(std::move(key_size));
	return total;
}

void NSROOT::algorithm::Algorithm::set_block_size(uint64_t block_size)
{
	this->block_size_ = block_size;
}
void NSROOT::algorithm::Algorithm::set_key_size(uint64_t key_size)
{
	this->key_size_ = key_size;
}
uint64_t NSROOT::algorithm::Algorithm::get_block_size() const
{
	return this->block_size_;
}
uint64_t NSROOT::algorithm::Algorithm::get_key_size() const
{
	return this->key_size_;
}

NSROOT::mode::Config::Config(const std::string& name, const std::map<std::string, ParamInfo> params)
	: name(name), params(params){}
std::string NSROOT::mode::Config::fmt_string()
{
	std::string fmt = this->name;
	fmt += '(';
	for (auto&[key, type_info] : this->params)
	{
		fmt += key;
		fmt += ":{";
		fmt += get_type_name(type_info.type);
		std::string msg = type_info.msg;
		for (auto cit = msg.begin(); cit != msg.end(); ++cit)
		{
			if (*cit == '\"' || *cit == '\\')
			{
				cit = msg.insert(cit, '\\');
			}
		}
		fmt += ", \"";
		fmt += msg;
		fmt += "\"},";
	}
	fmt.back() = ')';
	return fmt;
}

NSROOT::mode::Mode::Mode() {}
NSROOT::mode::Mode::Mode(const padding::Padding& padding) : padding_(padding.clone())
{
	if (this->padding_ == nullptr || this->padding_->fmt_string() == "")
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_SETTING_PADDING));
	}
};
NSROOT::mode::Mode::Mode(const std::unique_ptr<padding::Padding>& padding) : padding_(padding->clone())
{
	if (this->padding_ == nullptr || this->padding_->fmt_string() == "")
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_SETTING_PADDING));
	}
};
NSROOT::mode::Mode::Mode(std::unique_ptr<padding::Padding>&& padding): padding_(std::move(padding))
{
	if (this->padding_ == nullptr || this->padding_->fmt_string() == "")
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_SETTING_PADDING));
	}
};
NSROOT::mode::Mode::Mode(const Mode& other)
{
	this->padding_ = other.padding_->clone();
}
NSROOT::mode::Mode& NSROOT::mode::Mode::operator=(const Mode& other)
{
	this->padding_ = other.padding_->clone();
	return *this;
}
NSROOT::mode::Mode::Mode(Mode&& other) noexcept
{
	this->padding_ = std::move(other.padding_);
}
NSROOT::mode::Mode& NSROOT::mode::Mode::operator=(Mode&& other) noexcept
{
	this->padding_ = std::move(other.padding_);
	return *this;
}

std::unique_ptr<NSROOT::mode::Mode> NSROOT::mode::Mode::clone() const
{
	return std::make_unique<NSROOT::mode::Mode>(*this);
}
NSROOT::mode::Config NSROOT::mode::Mode::params_config()
{
	static const Config config = Config("", {});
	return config;
}
NSROOT::mode::Config NSROOT::mode::Mode::config() const
{
	return params_config();
}
std::string NSROOT::mode::Mode::fmt_string() const
{
	return std::string();
}
Value NSROOT::mode::Mode::serialize() const
{
	using dog_torch::serialize::tlv::MIBString;
	Value total = std::vector<Value>{};
	total.to_array().push_back(MIBString{ this->config().name });
	total.to_array().push_back(this->padding_->serialize());
	return total;
}
bool NSROOT::mode::Mode::set_uint64_param(const std::string& param, uint64_t value)
{
	return false;
}
bool NSROOT::mode::Mode::set_string_param(const std::string& param, const std::string& value)
{
	return false;
}
bool NSROOT::mode::Mode::set_binary_param(const std::string& param, const BinaryData& value)
{
	return false;
}
bool NSROOT::mode::Mode::set_padding(const padding::Padding& value)
{
	if (value.fmt_string() == "")
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_SETTING_PADDING));
	}
	this->padding_ = value.clone();
	return true;
}
bool NSROOT::mode::Mode::check(const algorithm::Algorithm& algorithm) const
{
	return false;
}

NSROOT::mode::crypt_func NSROOT::mode::Mode::get_mult_encrypt() const
{
	return crypt_func();
}
NSROOT::mode::crypt_func NSROOT::mode::Mode::get_mult_decrypt() const
{
	return crypt_func();
}

NSROOT::mode::stream_crypt_func NSROOT::mode::Mode::get_stream_encrypt() const
{
	return stream_crypt_func();
}
NSROOT::mode::stream_crypt_func NSROOT::mode::Mode::get_stream_decrypt() const
{
	return stream_crypt_func();
}

NSROOT::mode::streamp_crypt_func NSROOT::mode::Mode::get_streamp_encrypt() const
{
	return streamp_crypt_func();
}
NSROOT::mode::streamp_crypt_func NSROOT::mode::Mode::get_streamp_decrypt() const
{
	return streamp_crypt_func();
}

NSROOT::BlockCipher::BlockCipher() = default;
NSROOT::BlockCipher::BlockCipher(const algorithm::Algorithm& algorithm, const mode::Mode& mode) : algorithm_(algorithm.clone()), mode_(mode.clone()) {}
NSROOT::BlockCipher::BlockCipher(const BinaryData& key, const algorithm::Algorithm& algorithm, const mode::Mode& mode) 
	: Cipher(key), algorithm_(algorithm.clone()), mode_(mode.clone())
{
	this->init();
}
std::unique_ptr<Cipher> NSROOT::BlockCipher::clone() const
{
	return std::make_unique<BlockCipher>(this->ori_key_, *this->algorithm_, *this->mode_);
}
dog_torch::crypto::sym::block::BlockCipher::~BlockCipher() = default;
void NSROOT::BlockCipher::init()
{
	if (this->algorithm_ == nullptr || this->mode_ == nullptr)
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_SETTING_ALGORITHM_MODE));
	}
	if (!this->mode_->check(*this->algorithm_))
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_NOT_COMPATIBLE));
	}
	this->available_key_ = this->algorithm_->get_extend_key()(this->ori_key_, this->algorithm_->get_block_size(), this->algorithm_->get_key_size());
	this->is_effective_ = true;
}

bool NSROOT::BlockCipher::effective() const
{
	if (this->algorithm_ == nullptr || this->mode_ == nullptr)
	{
		return false;
	}
	if (!this->mode_->check(*this->algorithm_))
	{
		return false;
	}
	return true;
}

std::string NSROOT::BlockCipher::fmt_string() const
{
	return std::format("BlockCipher<{},{}>", this->algorithm_->fmt_string(), this->mode_->fmt_string());
}
Value NSROOT::BlockCipher::serialize() const
{
	using dog_torch::serialize::tlv::MIBString;
	Value tag_t = std::unordered_map<MIBString, Value>{};
	Value total = std::vector<Value>{};
	total.to_array().push_back(this->algorithm_->serialize());
	total.to_array().push_back(this->mode_->serialize());
	tag_t.to_object().insert({ MIBString{ "Block" } ,total });
	return tag_t;
}

NSROOT::algorithm::Algorithm& NSROOT::BlockCipher::algorithm()
{
	this->is_effective_ = false;
	return *this->algorithm_;
}
const NSROOT::algorithm::Algorithm& NSROOT::BlockCipher::const_algorithm() const
{
	return *this->algorithm_;
}
NSROOT::mode::Mode& NSROOT::BlockCipher::mode()
{
	this->is_effective_ = false;
	return *this->mode_;
}
const NSROOT::mode::Mode& NSROOT::BlockCipher::const_mode() const
{
	return *this->mode_;
}

BinaryData NSROOT::BlockCipher::encrypt(const BinaryData& plain)
{
	return this->mode_->get_mult_encrypt()(plain, this->available_key_, *this->algorithm_);
}
BinaryData NSROOT::BlockCipher::decrypt(const BinaryData& crypt)
{
	return this->mode_->get_mult_decrypt()(crypt, this->available_key_, *this->algorithm_);
}

void NSROOT::BlockCipher::encrypt_stream(std::istream& plain, uint64_t total, std::ostream& crypt)
{
	this->mode_->get_stream_encrypt()(plain, total, crypt, this->available_key_, *this->algorithm_);
}
void NSROOT::BlockCipher::decrypt_stream(std::istream& crypt, uint64_t total, std::ostream& plain)
{
	this->mode_->get_stream_decrypt()(crypt, total, plain, this->available_key_, *this->algorithm_);
}

void NSROOT::BlockCipher::encryptp_stream(PauseableChannel& pc, std::istream& plain, uint64_t total, std::ostream& crypt)
{
	this->mode_->get_streamp_encrypt()(pc, plain, total, crypt, this->available_key_, *this->algorithm_);
}
void NSROOT::BlockCipher::decryptp_stream(PauseableChannel& pc, std::istream& crypt, uint64_t total, std::ostream& plain)
{
	this->mode_->get_streamp_decrypt()(pc, crypt, total, plain, this->available_key_, *this->algorithm_);
}


#define NS_ROOT(name) dog_torch__crypto__sym__block__##name
#define NS_ALG(name) dog_torch__crypto__sym__block__algorithm__##name
#define NS_MODE(name) dog_torch__crypto__sym__block__mode__##name
#define NS_PADDING(name) dog_torch__crypto__sym__block__padding__##name
#define CRYPTO_BASE(name) dog_torch__crypto__##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

UTILS(CppString)* NS_ALG(Config_name)               (const LVALUE(NS_ALG(Config)) self)
{
	if (self == nullptr) return nullptr;
	return dog_torch::utils::to_c_style(self->name);
}
UTILS(CppString)* NS_ALG(Config_block_region)       (const LVALUE(NS_ALG(Config)) self)
{
	if (self == nullptr) return nullptr;
	return dog_torch::utils::to_c_style(self->block_size_region);
}
UTILS(CppString)* NS_ALG(Config_key_region)         (const LVALUE(NS_ALG(Config)) self)
{
	if (self == nullptr) return nullptr;
	return dog_torch::utils::to_c_style(self->key_size_region);
}

UTILS(CppString)* NS_ROOT(Algorithm_fmt_string)     (const LVALUE(NS_ROOT(Algorithm)) self)
{
	if (self == nullptr) return nullptr;
	return dog_torch::utils::to_c_style(self->fmt_string());
}
void NS_ROOT(Algorithm_delete)         (NS_ROOT(Algorithm)** self)
{
	DEFAULT_DESTOTY(self);
}

UTILS(CppString)* NS_MODE(Config_name)              (const LVALUE(NS_MODE(Config)) self)
{
	if (self == nullptr) return nullptr;
	return dog_torch::utils::to_c_style(self->name);
}
CRYPTO_BASE(ParamInfoTreeMap)* NS_MODE(Config_params)            (const LVALUE(NS_MODE(Config)) self)
{
	if (self == nullptr) return nullptr;
	return new CRYPTO_BASE(ParamInfoTreeMap)(self->params);
}
UTILS(CppString)* NS_MODE(Mode_fmt_string)          (const LVALUE(NS_ROOT(Mode)) self)
{
	if (self == nullptr) return nullptr;
	return dog_torch::utils::to_c_style(self->fmt_string());
}
void NS_ROOT(Mode_delete)              (NS_ROOT(Mode)** self)
{
	DEFAULT_DESTOTY(self);
}

UTILS(CppString)* NS_PADDING(Config_name)           (const LVALUE(NS_PADDING(Config)) self)
{
	if (self == nullptr) return nullptr;
	return dog_torch::utils::to_c_style(self->name);
}
UTILS(CppString)* NS_PADDING(Config_block_region)   (const LVALUE(NS_PADDING(Config)) self)
{
	if (self == nullptr) return nullptr;
	return dog_torch::utils::to_c_style(self->allowed_block_size_region);
}

NS_ROOT(BlockCipher)* NS_ROOT(BlockCipher_create)  (LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(NS_ROOT(Algorithm)) alg, const LVALUE(NS_ROOT(Mode)) mode)
{
	if (alg == nullptr)
	{
		dog_torch::utils::CppResultSet_reset(result_set, -1, "algorithm is null");
		return nullptr;
	}
	if (mode == nullptr)
	{
		dog_torch::utils::CppResultSet_reset(result_set, -2, "mode is null");
	}
	try
	{
		return new NS_ROOT(BlockCipher){ *alg, *mode };
	}
	catch(const std::exception & e)
	{
		dog_torch::utils::CppResultSet_reset(result_set, -3, e.what());
		return nullptr;
	}
}
void NS_ROOT(BlockCipher_delete)       (NS_ROOT(BlockCipher)** self)
{
	DEFAULT_DESTOTY(self);
}
#undef NS_ROOT
#undef NS_ALG
#undef NS_MODE
#undef NS_PADDING
#undef CRYPTO_BASE
#undef SERIALIZE
#undef UTILS