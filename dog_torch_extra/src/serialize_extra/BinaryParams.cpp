#include "serialize_extra/BinaryParams.h"

namespace NSROOT = dog_torch::serialize;

NSROOT::BinaryParams NSROOT::BinaryParams::from_utf8()
{
	auto params = BinaryParams();
	params.type_ = Type::UTF_8;
	return params;
}
NSROOT::BinaryParams NSROOT::BinaryParams::from_binary()
{
	auto params = BinaryParams();
	params.type_ = Type::Binary;
	return params;
}

NSROOT::BinaryParams NSROOT::BinaryParams::from_hex(bool is_upper)
{
	auto params = BinaryParams();
	params.type_ = Type::Hex;
	params.params_.push_back(is_upper);
	return params;
}
NSROOT::BinaryParams NSROOT::BinaryParams::from_base64(char a, char b, char c)
{
	auto params = BinaryParams();
	params.type_ = Type::Hex;
	params.params_.push_back(a);
	params.params_.push_back(b);
	params.params_.push_back(c);
	return params;
}
std::string NSROOT::BinaryParams::fmt_BinaryData(const BinaryData& data)
{
	switch (type_)
	{
	case Type::Binary:
		return data.to_bin_string();
	case Type::Hex:
		return data.to_hex_string(std::get<bool>(this->params_[0]));
	case Type::Base64:
		return data.to_base64_string(
			std::get<char>(this->params_[0]), 
			std::get<char>(this->params_[1]), 
			std::get<char>(this->params_[2])
		);
	default:
		return data.to_string();
	}
}

std::string NSROOT::BinaryParams::fmt_string()
{
	switch(type_)
	{
	case Type::Hex:
		return std::format("{}:{}", 
			type_fmt_string(this->type_), 
			(std::get<bool>(this->params_[0]) ? "upper" : "lower")
		);
	case Type::Base64:
		return std::format("{}:{}{}{}",
			type_fmt_string(this->type_),
			std::get<char>(this->params_[0]),
			std::get<char>(this->params_[1]),
			std::get<char>(this->params_[2])
		);
	default:
		return type_fmt_string(this->type_);
	}
}

std::string NSROOT::type_fmt_string(Type type)
{
	switch (type)
	{
	case Type::UTF_8: return "UTF-8";
	case Type::Binary: return "Binary";
	case Type::Hex: return "Hex";
	case Type::Base64: return "Base64";
	}
}
