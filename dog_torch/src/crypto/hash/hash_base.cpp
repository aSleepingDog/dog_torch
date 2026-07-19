#include "crypto/hash/hash_base.h"

namespace NSROOT = dog_torch::crypto::hash;

NSROOT::algorithm::Config::Config(const std::string& name, const std::string& region, const std::map<std::string, ParamType>& params) 
	: name(name), region(region), params(params)
{}

NSROOT::algorithm::Config::Config(const Config& config)
{
	this->name = config.name;
	this->region = config.region;
	this->params = config.params;
}
NSROOT::algorithm::Config& NSROOT::algorithm::Config::operator=(const Config& config)
{
	this->name = config.name;
	this->region = config.region;
	this->params = config.params;
	return *this;
}

NSROOT::algorithm::Config::Config(Config&& config) noexcept
{
	this->name = std::move(config.name);
	this->region = std::move(config.region);
	this->params = std::move(config.params);
}
NSROOT::algorithm::Config& NSROOT::algorithm::Config::operator=(Config && config) noexcept
{
	this->name = std::move(config.name);
	this->region = std::move(config.region);
	this->params = std::move(config.params);
	return *this;
}


NSROOT::algorithm::Algorithm::Algorithm(uint64_t effective) : effective(effective) {}

NSROOT::algorithm::Algorithm::Algorithm(const Algorithm& algorithm)
{
	this->effective = algorithm.effective;
}
NSROOT::algorithm::Algorithm& NSROOT::algorithm::Algorithm::operator=(const Algorithm & algorithm)
{
	this->effective = algorithm.effective;
	return *this;
}
NSROOT::algorithm::Algorithm::Algorithm(Algorithm&& algorithm) noexcept
{
	this->effective = algorithm.effective;
}
NSROOT::algorithm::Algorithm& NSROOT::algorithm::Algorithm::operator=(Algorithm && algorithm) noexcept
{
	this->effective = algorithm.effective;
	return *this;
}

NSROOT::algorithm::Config NSROOT::algorithm::Algorithm::config() const
{
	return Config("", "", {});
}

std::string NSROOT::algorithm::Algorithm::fmt_string() const
{
	return "";
}

void NSROOT::algorithm::Algorithm::init()
{}

NSROOT::BinaryData NSROOT::algorithm::Algorithm::init_data() const
{
	return BinaryData();
}

NSROOT::algorithm::update_func NSROOT::algorithm::Algorithm::get_update() const
{
	return update_func();
}

NSROOT::algorithm::trims_func NSROOT::algorithm::Algorithm::get_trims() const
{
	return trims_func();
}

std::unique_ptr<NSROOT::algorithm::Algorithm> NSROOT::algorithm::Algorithm::clone() const
{
	return std::make_unique<Algorithm>(*this);
}

uint64_t NSROOT::algorithm::Algorithm::get_block_size() const
{
	return 0;
}

uint64_t NSROOT::algorithm::Algorithm::get_out_size() const
{
	return 0;
}

bool NSROOT::algorithm::Algorithm::have_next_block(uint64_t data_pos, uint64_t data_total)
{
	return false;
}

NSROOT::BinaryData NSROOT::algorithm::Algorithm::next_block(const BinaryData& data, uint64_t start, uint64_t& data_pos, uint64_t data_total)
{
	return BinaryData();
}

NSROOT::BinaryData NSROOT::algorithm::Algorithm::next_block(std::istream& data, uint64_t& data_pos, uint64_t data_total)
{
	return BinaryData();
}

NSROOT::Generator::Generator(const std::unique_ptr<algorithm::Algorithm>& algorithm) : algorithm_(algorithm->clone())
{
	this->init();
}
NSROOT::Generator::Generator(std::unique_ptr<algorithm::Algorithm>&& algorithm) noexcept : algorithm_(std::move(algorithm))
{
    this->init();
}
dog_torch::crypto::hash::Generator::Generator(const algorithm::Algorithm& algorithm) : algorithm_(algorithm.clone())
{
	this->init();
}
NSROOT::Generator::Generator(const Generator& other)
{
	this->algorithm_ = other.algorithm_->clone();
	this->hash_value_ = other.hash_value_;
}
NSROOT::Generator& NSROOT::Generator::operator=(const Generator & other)
{
	this->algorithm_ = other.algorithm_->clone();
	this->hash_value_ = other.hash_value_;
	return *this;
}
NSROOT::Generator::Generator(Generator&& other) noexcept
{
	this->algorithm_ = std::move(other.algorithm_);
	this->hash_value_ = other.hash_value_;
}
NSROOT::Generator& NSROOT::Generator::operator=(Generator && other) noexcept
{
	if (this == &other) return *this;
	this->algorithm_ = std::move(other.algorithm_);
	this->hash_value_ = other.hash_value_;
	return *this;
}
void NSROOT::Generator::init()
{
    this->algorithm_->init();
	this->hash_value_ = this->algorithm_->init_data();
}
NSROOT::BinaryData NSROOT::Generator::calculate(const BinaryData& source)
{
	auto update_func = this->algorithm_->get_update();
	auto trims_func = this->algorithm_->get_trims();
	uint64_t pos = 0;
	uint64_t total = source.size();
	do
	{
		BinaryData block = this->algorithm_->next_block(source, pos, pos, total);
		update_func(block, this->hash_value_);
	} while (this->algorithm_->have_next_block(pos, total));
	trims_func(this->hash_value_);
	auto res = this->hash_value_;
	this->init();
	return res;
}
NSROOT::BinaryData NSROOT::Generator::calculate(std::istream& source, uint64_t total)
{
	auto update_func = this->algorithm_->get_update();
	auto trims_func = this->algorithm_->get_trims();
	uint64_t pos = 0;
	do
	{
		BinaryData block = this->algorithm_->next_block(source, pos, total);
		update_func(block, this->hash_value_);
	} while (this->algorithm_->have_next_block(pos, total));
	trims_func(this->hash_value_);
	auto res = this->hash_value_;
	this->init();
	return res;
}

NSROOT::BinaryData NSROOT::Generator::calculate(PauseableChannel& pc, std::istream& source, uint64_t total)
{
	pc.start();
	auto update_func = this->algorithm_->get_update();
	auto trims_func = this->algorithm_->get_trims();
	uint64_t pos = 0;
	do
	{
		if (pc.check_status()) break;
		BinaryData block = this->algorithm_->next_block(source, pos, total);
		update_func(block, this->hash_value_);
		pc.add_progress(block.size() * 1.0 / total);
	} while (this->algorithm_->have_next_block(pos, total));
	trims_func(this->hash_value_);
	auto res = this->hash_value_;
	this->init();
	pc.set_progress(1.0);
	pc.stop();
	return res;
}

NSROOT::BinaryData NSROOT::Generator::calculate_with(PauseableChannel& pc, Generator& self, std::istream& source, uint64_t total)
{
	return self.calculate(pc, source, total);
}

std::string NSROOT::Generator::fmt_string() const
{
	return std::format("Hash<{}>", this->algorithm_->fmt_string());
}

#define NAMESPACE(name) dog_torch__crypto__hash__##name
#define CRYPTO_BASE(name) dog_torch__crypto__##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

UTILS(CppString)*NAMESPACE(Config_name)(const LVALUE(NAMESPACE(Config))config)
{
	return dog_torch::utils::to_c_style(config->name);
}

UTILS(CppString)*NAMESPACE(Config_region)(const LVALUE(NAMESPACE(Config))config)
{
	return dog_torch::utils::to_c_style(config->region);
}

CRYPTO_BASE(ParamTypeTreeMap)* NAMESPACE(Config_params)(const LVALUE(NAMESPACE(Config))config)
{
	return new CRYPTO_BASE(ParamTypeTreeMap)(config->params);
}

void NAMESPACE(Algorithm_delete)(NAMESPACE(Algorithm)** self)
{
	DEFAULT_DESTOTY(self);
}

UTILS(CppString)* NAMESPACE(Algorithm_fmt_string)(const LVALUE(NAMESPACE(Algorithm))self)
{
	if (self == nullptr) return nullptr;
	return dog_torch::utils::to_c_style(self->fmt_string());
}

NAMESPACE(Generator)* NAMESPACE(Generator_create_copy)(const LVALUE(NAMESPACE(Algorithm))alg)
{
	if (alg == nullptr) return nullptr;
	return new NAMESPACE(Generator){ *alg };
}
NAMESPACE(Generator)* NAMESPACE(Generator_create_move)(NAMESPACE(Algorithm)** alg)
{
	if (*alg == nullptr) return nullptr;
	auto res = new NAMESPACE(Generator){ std::move(**alg) };
	NAMESPACE(Algorithm_delete)(alg);
	return res;
}
void NAMESPACE(Generator_delete)(NAMESPACE(Generator)** self)
{
	DEFAULT_DESTOTY(self);
}

UTILS(CppString)* NAMESPACE(Generator_fmt_string)(const LVALUE(NAMESPACE(Generator))self)
{
	if (self == nullptr) return nullptr;
	return dog_torch::utils::to_c_style(self->fmt_string());
}

SERIALIZE(BinaryData)* NAMESPACE(Generator_calculate_binary)(LVALUE(NAMESPACE(Generator))self, const LVALUE(SERIALIZE(BinaryData))data)
{
	if (self == nullptr) return nullptr;
	if (data == nullptr)
	{
		return new SERIALIZE(BinaryData){ self->calculate({"",0}) };
	}
	return new SERIALIZE(BinaryData){ self->calculate(*data) };
}
SERIALIZE(BinaryData)* NAMESPACE(Generator_calculate_file)(LVALUE(UTILS(CppResultSet)) result_set, LVALUE(NAMESPACE(Generator)) self, const LVALUE(UTILS(CppString)) path)
{
	using dog_torch::utils::CppResultSet_reset;
	using dog_torch::utils::to_string;
	if (self == nullptr)
	{
		CppResultSet_reset(result_set, -1, "self is null");
		return nullptr;
	}
	if (path == nullptr)
	{
		CppResultSet_reset(result_set, -2, "path is null");
		return nullptr;
	}
	std::string path_str = to_string(path);
	if (!std::filesystem::exists(path_str))
	{
		CppResultSet_reset(result_set, -3, "path is not exists");
		return nullptr;
	}
	std::ifstream file(path_str, std::ios::binary);
	uint64_t file_size = std::filesystem::file_size(path_str);
	return new SERIALIZE(BinaryData){ self->calculate(file,file_size) };
}

#undef NAMESPACE
#undef CRYPTO_BASE
#undef SERIALIZE
#undef UTILS