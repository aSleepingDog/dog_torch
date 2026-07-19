#include "serialize/tlv.h"

namespace NSROOT = dog_torch::serialize::tlv;

using dog_torch::utils::from_c_str;
using dog_torch::utils::from_uint64;
using dog_torch::utils::array_to_view;
using dog_torch::utils::operator+;
constexpr auto ERROR_WRONG_TYPE = from_c_str("Value is not ");
constexpr auto ERROR_WRONG_TAG = from_c_str("Invalid tag");
constexpr auto ERROR_UNSUPPORT_FLOAT = from_c_str("Invalid float tag ");

NSROOT::MIBString::MIBString(const std::string& str, uint64_t mid) : string(str), mib(mid) {}
NSROOT::MIBString::MIBString(std::string&& str, uint64_t mid) : string(std::move(str)), mib(mid) {}

bool NSROOT::MIBString::operator==(const MIBString& other) const
{
	return this->mib == other.mib && this->string == other.string;
}

size_t std::hash<NSROOT::MIBString>::operator()(const NSROOT::MIBString& value) const
{
	size_t h0 = std::hash<uint64_t>{}(value.mib);
	size_t h1 = std::hash<std::string>{}(value.string);
	return dog_torch::utils::hash::combine(h0, h1);
}
size_t std::hash<NSROOT::Value>::operator()(const NSROOT::Value& value_) const
{
	const auto& value = value_.get();
	size_t hash = 0;
	if (value.index() == 0)
	{
		return 0;
	}
	else if (value.index() == 1)
	{
		return std::hash<bool>{}(std::get<bool>(value));
	}
	else if (value.index() == 2)
	{
		return std::hash<NSROOT::Integer64>{}(std::get<NSROOT::Integer64>(value));
	}
	else if (value.index() == 3)
	{
		return std::hash<double>{}(std::get<double>(value));
	}
	else if (value.index() == 4)
	{
		const std::vector<uint8_t>& v = std::get<std::vector<uint8_t>>(value);
		return std::hash<std::string>{}(std::string(v.begin(), v.end()));
	}
	else if (value.index() == 5)
	{
		return std::hash<NSROOT::MIBString>{}(std::get<NSROOT::MIBString>(value));
	}
	else if (value.index() == 6)
	{
		const auto& v = std::get<std::vector<NSROOT::Value>>(value);
		for (const auto& e : v)
		{
			hash = dog_torch::utils::hash::combine(hash, (*this)(e));
		}
	}
	else if (value.index() == 7)
	{
		const auto& v = std::get<std::unordered_set<NSROOT::Value>>(value);
		for (const auto& e : v)
		{
			hash = dog_torch::utils::hash::combine(hash, (*this)(e));
		}
	}
	else if (value.index() == 8)
	{
		const auto& v = std::get<std::unordered_map<NSROOT::Integer64, NSROOT::Value>>(value);
		for (const auto& e : v)
		{
			hash = dog_torch::utils::hash::combine(hash, std::hash<NSROOT::Integer64>{}(e.first));
			hash = dog_torch::utils::hash::combine(hash, (*this)(e.second));
		}
	}
	else if (value.index() == 9)
	{
		const auto& v = std::get<std::unordered_map<NSROOT::Value, NSROOT::Value>>(value);
		for (const auto& e : v)
		{
			hash = dog_torch::utils::hash::combine(hash, (*this)(e.first));
			hash = dog_torch::utils::hash::combine(hash, (*this)(e.second));
		}
	}
	else if (value.index() == 10)
	{
		const auto& v = std::get<std::unordered_map<NSROOT::MIBString, NSROOT::Value>>(value);
		for (const auto& e : v)
		{
			hash = dog_torch::utils::hash::combine(hash, std::hash<NSROOT::MIBString>{}(e.first));
			hash = dog_torch::utils::hash::combine(hash, (*this)(e.second));
		}
	}
	return hash;
}

NSROOT::Value::Value()
{
	this->value_ = nullptr;
}
NSROOT::Value::Value(std::nullptr_t) : Value() {}
NSROOT::Value::Value(bool value)
{
	this->value_ = value;
}

NSROOT::Value::Value(const Integer64& value)
{
	this->value_ = value;
}
NSROOT::Value::Value(Integer64&& value)
{
	this->value_ = std::move(value);
}
NSROOT::Value::Value(char sign, uint64_t number)
{
	this->value_ = Integer64{ sign * number };
}

NSROOT::Value::Value(double value)
{
	this->value_ = value;
}

NSROOT::Value::Value(const std::vector<uint8_t>& value)
{
	this->value_ = value;
}
NSROOT::Value::Value(std::vector<uint8_t>&& value)
{
	this->value_ = std::move(value);
}

NSROOT::Value::Value(const MIBString& value)
{
	this->value_ = value;
}
NSROOT::Value::Value(MIBString&& value)
{
	this->value_ = std::move(value);
}

NSROOT::Value::Value(const std::vector<NSROOT::Value>& value)
{
	this->value_ = value;
}
NSROOT::Value::Value(std::vector<NSROOT::Value>&& value)
{
	this->value_ = std::move(value);
}

NSROOT::Value::Value(const std::unordered_set<NSROOT::Value>& value)
{
	this->value_ = value;
}
NSROOT::Value::Value(std::unordered_set<NSROOT::Value>&& value)
{
	this->value_ = std::move(value);
}

NSROOT::Value::Value(const std::unordered_map<Integer64, NSROOT::Value>& value)
{
	this->value_ = value;
}
NSROOT::Value::Value(std::unordered_map<Integer64, NSROOT::Value>&& value)
{
	this->value_ = std::move(value);
}

NSROOT::Value::Value(const std::unordered_map<NSROOT::Value, NSROOT::Value>& value)
{
	this->value_ = value;
}
NSROOT::Value::Value(std::unordered_map<NSROOT::Value, NSROOT::Value>&& value)
{
	this->value_ = std::move(value);
}

NSROOT::Value::Value(const std::unordered_map<MIBString, NSROOT::Value>& value)
{
	this->value_ = value;
}
NSROOT::Value::Value(std::unordered_map<MIBString, NSROOT::Value>&& value)
{
	this->value_ = std::move(value);
}

NSROOT::Value::Value(const Value& other) = default;
NSROOT::Value& NSROOT::Value::operator=(const Value& other) = default;
NSROOT::Value::Value(Value&& other) noexcept = default;
NSROOT::Value& NSROOT::Value::operator=(Value&& other) noexcept = default;

const NSROOT::Value::_store& NSROOT::Value::get() const
{
	return this->value_;
}

NSROOT::Value::_store& NSROOT::Value::get()
{
	return this->value_;
}

bool NSROOT::Value::operator==(const Value& other) const
{
	if (this->value_.index() != other.value_.index())
	{
		return false;
	}
	auto visitor = [](const auto& a, const auto& b) -> bool {
		if constexpr (!std::is_same_v<decltype(a), decltype(b)>)
		{
			return false;
		}
		else
		{
			if constexpr (std::is_same_v<std::decay_t<decltype(a)>, std::nullptr_t>)
			{
				return true;
			}
			else
			{
				return a == b;
			}
		}
		};
	return std::visit(visitor, this->value_, other.value_);
}

NSROOT::Type NSROOT::Value::type() const
{
	return (Type)(this->value_.index());
}

std::nullptr_t NSROOT::Value::to_null() const
{
	if (this->value_.index() != 0)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("null"))));
	return std::get<std::nullptr_t>(this->value_);
}

bool& NSROOT::Value::to_bool()
{
	if (this->value_.index() != 1)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("bool"))));
	return std::get<bool>(this->value_);
}
bool NSROOT::Value::to_bool() const
{
	if (this->value_.index() != 1)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("bool"))));
	return std::get<bool>(this->value_);
}

NSROOT::Integer64& NSROOT::Value::to_integer()
{
	if (this->value_.index() != 2)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("integer"))));
	return std::get<NSROOT::Integer64>(this->value_);
}
const NSROOT::Integer64& NSROOT::Value::to_integer() const
{
	if (this->value_.index() != 2)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("integer"))));
	return std::get<NSROOT::Integer64>(this->value_);
}

double& NSROOT::Value::to_float()
{
	if (this->value_.index() != 3)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("float"))));
	return std::get<double>(this->value_);
}
double NSROOT::Value::to_float() const
{
	if (this->value_.index() != 3)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("float"))));
	return std::get<double>(this->value_);
}

std::vector<uint8_t>& NSROOT::Value::to_binary()
{
	if (this->value_.index() != 4)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("binary"))));
	return std::get<std::vector<uint8_t>>(this->value_);
}
const std::vector<uint8_t>& NSROOT::Value::to_binary() const
{
	if (this->value_.index() != 4)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("binary"))));
	return std::get<std::vector<uint8_t>>(this->value_);
}

NSROOT::MIBString& NSROOT::Value::to_string()
{
	if (this->value_.index() != 5)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("string"))));
	return std::get<NSROOT::MIBString>(this->value_);
}
const NSROOT::MIBString& NSROOT::Value::to_string() const
{
	if (this->value_.index() != 5)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("string"))));
	return std::get<NSROOT::MIBString>(this->value_);
}

std::vector<NSROOT::Value>& NSROOT::Value::to_array()
{
	if (this->value_.index() != 6)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("array"))));
	return std::get<std::vector<NSROOT::Value>>(this->value_);
}
const std::vector<NSROOT::Value>& NSROOT::Value::to_array() const
{
	if (this->value_.index() != 6)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("array"))));
	return std::get<std::vector<NSROOT::Value>>(this->value_);
}

std::unordered_set<NSROOT::Value>& NSROOT::Value::to_set()
{
	if (this->value_.index() != 7)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("set"))));
	return std::get<std::unordered_set<NSROOT::Value>>(this->value_);
}
const std::unordered_set<NSROOT::Value>& NSROOT::Value::to_set() const
{
	if (this->value_.index() != 7)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("set"))));
	return std::get<std::unordered_set<NSROOT::Value>>(this->value_);
}

std::unordered_map<NSROOT::Integer64, NSROOT::Value>& NSROOT::Value::to_enum()
{
	if (this->value_.index() != 8)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("enum"))));
	return std::get<std::unordered_map<Integer64, Value>>(this->value_);
}
const std::unordered_map<NSROOT::Integer64, NSROOT::Value>& NSROOT::Value::to_enum() const
{
	if (this->value_.index() != 8)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("enum"))));
	return std::get<std::unordered_map<Integer64, Value>>(this->value_);
}

std::unordered_map<NSROOT::Value, NSROOT::Value>& NSROOT::Value::to_map()
{
	if (this->value_.index() != 9)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("map"))));
	return std::get<std::unordered_map<Value, Value>>(this->value_);
}
const std::unordered_map<NSROOT::Value, NSROOT::Value>& NSROOT::Value::to_map() const
{
	if (this->value_.index() != 9)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("map"))));
	return std::get<std::unordered_map<Value, Value>>(this->value_);
}

std::unordered_map<NSROOT::MIBString, NSROOT::Value>& NSROOT::Value::to_object()
{
	if (this->value_.index() != 10)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("object"))));
	return std::get<std::unordered_map<MIBString, Value>>(this->value_);
}
const std::unordered_map<NSROOT::MIBString, NSROOT::Value> NSROOT::Value::to_object() const
{
	if (this->value_.index() != 10)
		throw DOG_EXCEPTION(array_to_view((ERROR_WRONG_TYPE + from_c_str("object"))));
	return std::get<std::unordered_map<MIBString, Value>>(this->value_);
}

NSROOT::Value NSROOT::Value::parse(std::vector<uint8_t>::const_iterator& pos, std::vector<uint8_t>::const_iterator end)
{
	uint8_t tag = *pos++;
	if ((tag >> 4) == 0b0010)
	{
		return Value(nullptr);
	}
	else if ((tag >> 4) == 0b0011)
	{
		return Value((tag & 0b1111) == 0 ? false : true);
	}
	else if ((tag >> 5) == 0b010)
	{
		char sign = tag >> 3 & 1 ? -1 : 1;
		uint8_t llen = (tag & 0b111) + 1;
		uint64_t number = 0;
		for (uint8_t i = 0; i < llen; i++)
		{
			number <<= 8;
			number |= *pos++;
		}
		return Value(sign, number);
	}
	else if ((tag >> 5) == 0b011)
	{
		if ((tag & 0b11) == 0b00 || (tag & 0b11) == 0b11)
		{
			throw DOG_EXCEPTION(array_to_view(ERROR_UNSUPPORT_FLOAT));
		}
		else if ((tag & 0b11) == 0b01)
		{
			float number = 0;
			for (uint8_t i = 0; i < 4; i++)
			{
				uint8_t t = *pos++;
				memset(&number + i, t, 1);
			}
			return Value(number);
		}
		else if ((tag & 0b11) == 0b10)
		{
			double number = 0;
			for (uint8_t i = 0; i < 8; i++)
			{
				uint8_t t = *pos++;
				memset(&number + i, t, 1);
			}
			return Value(number);
		}
		else
		{
			throw DOG_EXCEPTION(array_to_view(ERROR_WRONG_TAG));
		}
	}
	else if ((tag >> 5) == 0b100)
	{
		uint8_t llen = (tag & 0b111) + 1;
		uint64_t size = 0;
		for (uint8_t i = 0; i < llen; i++)
		{
			size <<= 8;
			size |= *pos++;
		}
		std::vector<uint8_t> value(size);
		for (uint64_t i = 0; i < size; i++)
		{
			value[i] = *pos++;
		}
		return Value(value);
	}
	else if ((tag >> 5) == 0b101)
	{
		uint64_t mib = 106;
		if (((tag >> 3) & 0b11))
		{
			uint8_t mlen = 1 << ((tag >> 3) & 0b11);
			for (uint8_t i = 0; i < mlen; i++)
			{
				mib <<= 8;
				mib |= *pos++;
			}
		}
		uint8_t llen = (tag & 0b111) + 1;
		uint64_t size = 0;
		for (uint8_t i = 0; i < llen; i++)
		{
			size <<= 8;
			size |= *pos++;
		}
		std::string value(size, 0);
		for (uint64_t i = 0; i < size; i++)
		{
			value[i] = *pos++;
		}
		return Value(MIBString{ std::move(value),mib });
	}
	else if ((tag >> 6) == 0b11)
	{
		uint8_t llen = (tag & 0b111) + 1;
		uint64_t size = 0;
		for (uint8_t i = 0; i < llen; i++)
		{
			size <<= 8;
			size |= *pos++;
		}
		if (((tag >> 3) & 0b111) == 0b000)
		{
			std::vector<Value> value(size);
			for (uint64_t i = 0; i < size; i++)
			{
				value[i] = Value::parse(pos, end);
			}
			return Value(value);
		}
		else if (((tag >> 3) & 0b111) == 0b001)
		{
			std::unordered_set<Value> value(size);
			for (uint64_t i = 0; i < size; i++)
			{
				value.insert(Value::parse(pos, end));
			}
			return Value(value);
		}
		else if (((tag >> 3) & 0b111) == 0b101)
		{
			std::unordered_map<Integer64, Value> value(size);
			for (uint64_t i = 0; i < size; i++)
			{
				Integer64 key = Value::parse(pos, end).to_integer();
				value[key] = Value::parse(pos, end);
			}
			return Value(value);
		}
		else if (((tag >> 3) & 0b111) == 0b010)
		{
			std::unordered_map<Value, Value> value(size);
			for (uint64_t i = 0; i < size; i++)
			{
				Value key = Value::parse(pos, end);
				value[key] = Value::parse(pos, end);
			}
			return Value(value);
		}
		else if (((tag >> 3) & 0b111) == 0b011)
		{
			std::unordered_map<MIBString, Value> value(size);
			for (uint64_t i = 0; i < size; i++)
			{
				MIBString key = Value::parse(pos, end).to_string();
				value[key] = Value::parse(pos, end);
			}
			return Value(value);
		}
		else
		{
			throw DOG_EXCEPTION(array_to_view(ERROR_WRONG_TAG));
		}
	}
	else
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_WRONG_TAG));
	}
}

NSROOT::Value NSROOT::Value::parse(std::istream& input)
{
	auto next = [&input]() -> uint8_t
		{
			return static_cast<uint8_t>(input.get());
		};
	uint8_t tag = next();
	if ((tag >> 4) == 0b0010)
	{
		return Value(nullptr);
	}
	else if ((tag >> 4) == 0b0011)
	{
		return Value((tag & 0b1111) == 0 ? false : true);
	}
	else if ((tag >> 5) == 0b010)
	{
		char sign = tag >> 3 & 1 ? -1 : 1;
		uint8_t llen = (tag & 0b111) + 1;
		uint64_t number = 0;
		for (uint8_t i = 0; i < llen; i++)
		{
			number <<= 8;
			number |= next();
		}
		return Value(sign, number);
	}
	else if ((tag >> 5) == 0b011)
	{
		if ((tag & 0b11) == 0b00 || (tag & 0b11) == 0b11)
		{
			throw DOG_EXCEPTION(array_to_view(ERROR_UNSUPPORT_FLOAT));
		}
		else if ((tag & 0b11) == 0b01)
		{
			float number = 0;
			for (uint8_t i = 0; i < 4; i++)
			{
				uint8_t t = next();
				memset(&number + i, t, 1);
			}
			return Value(number);
		}
		else if ((tag & 0b11) == 0b10)
		{
			double number = 0;
			for (uint8_t i = 0; i < 8; i++)
			{
				uint8_t t = next();
				memset(&number + i, t, 1);
			}
			return Value(number);
		}
		else
		{
			throw DOG_EXCEPTION(array_to_view(ERROR_WRONG_TAG));
		}
	}
	else if ((tag >> 5) == 0b100)
	{
		uint8_t llen = (tag & 0b111) + 1;
		uint64_t size = 0;
		for (uint8_t i = 0; i < llen; i++)
		{
			size <<= 8;
			size |= next();
		}
		std::vector<uint8_t> value(size);
		for (uint64_t i = 0; i < size; i++)
		{
			value[i] = next();
		}
		return Value(value);
	}
	else if ((tag >> 5) == 0b101)
	{
		uint64_t mib = 106;
		if (((tag >> 3) & 0b11))
		{
			uint8_t mlen = 1 << ((tag >> 3) & 0b11);
			for (uint8_t i = 0; i < mlen; i++)
			{
				mib <<= 8;
				mib |= next();
			}
		}
		uint8_t llen = (tag & 0b111) + 1;
		uint64_t size = 0;
		for (uint8_t i = 0; i < llen; i++)
		{
			size <<= 8;
			size |= next();
		}
		std::string value(size, 0);
		for (uint64_t i = 0; i < size; i++)
		{
			value[i] = next();
		}
		return Value(MIBString{ std::move(value),mib });
	}
	else if ((tag >> 6) == 0b11)
	{
		uint8_t llen = (tag & 0b111) + 1;
		uint64_t size = 0;
		for (uint8_t i = 0; i < llen; i++)
		{
			size <<= 8;
			size |= next();
		}
		if (((tag >> 3) & 0b111) == 0b000)
		{
			std::vector<Value> value(size);
			for (uint64_t i = 0; i < size; i++)
			{
				value[i] = Value::parse(input);
			}
			return Value(value);
		}
		else if (((tag >> 3) & 0b111) == 0b001)
		{
			std::unordered_set<Value> value(size);
			for (uint64_t i = 0; i < size; i++)
			{
				value.insert(Value::parse(input));
			}
			return Value(value);
		}
		else if (((tag >> 3) & 0b111) == 0b101)
		{
			std::unordered_map<Integer64, Value> value(size);
			for (uint64_t i = 0; i < size; i++)
			{
				Integer64 key = Value::parse(input).to_integer();
				value[key] = Value::parse(input);
			}
			return Value(value);
		}
		else if (((tag >> 3) & 0b111) == 0b010)
		{
			std::unordered_map<Value, Value> value(size);
			for (uint64_t i = 0; i < size; i++)
			{
				Value key = Value::parse(input);
				value[key] = Value::parse(input);
			}
			return Value(value);
		}
		else if (((tag >> 3) & 0b111) == 0b011)
		{
			std::unordered_map<MIBString, Value> value(size);
			for (uint64_t i = 0; i < size; i++)
			{
				MIBString key = Value::parse(input).to_string();
				value[key] = Value::parse(input);
			}
			return Value(value);
		}
		else
		{
			throw DOG_EXCEPTION(array_to_view(ERROR_WRONG_TAG));
		}
	}
	else
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_WRONG_TAG));
	}
}

std::vector<uint8_t> NSROOT::Value::serialize() const
{
	using namespace dog_torch::math::integer;
	std::vector<uint8_t> result;
	uint8_t tag = 0;
	if (this->value_.index() == 0)
	{
		result.push_back(0b00100000);
	}
	else if (this->value_.index() == 1)
	{
		tag = 0b00110000;
		tag |= this->to_bool() ? 0b1111 : 0b0000;
	}
	else if (this->value_.index() == 2)
	{
		tag = 0b01000000;
		auto numpack = this->to_integer();
		char sign = numpack.sign >= 0 ? 0 : 1;
		tag |= sign << 3;
		uint8_t len = available_size(numpack.number);
		tag |= len - 1;
		result.push_back(tag);
		for (uint8_t i = 0; i < len; ++i)
		{
			result.push_back(pick_byte(numpack.number, len - i - 1));
		}
	}
	else if (this->value_.index() == 3)
	{
		tag = 0b01100010;
		double number = this->to_float();
		uint64_t* ptr = (uint64_t*)&number;
		result.push_back(tag);
		for (uint8_t i = 0; i < 8; ++i)
		{
			result.push_back(pick_byte(*ptr, 8 - i - 1));
		}
	}
	else if (this->value_.index() == 4)
	{
		tag = 0b10000000;
		auto bytes = this->to_binary();
		uint64_t size = bytes.size();
		uint8_t llen = available_size(size);
		tag |= llen - 1;
		result.push_back(tag);
		for (uint8_t i = 0; i < llen; ++i)
		{
			result.push_back(pick_byte(size, llen - i - 1));
		}
		for (uint64_t i = 0; i < size; ++i)
		{
			result.push_back(bytes[i]);
		}
	}
	else if (this->value_.index() == 5)
	{
		tag = 0b10100000;
		auto mibstr = this->to_string();
		if (mibstr.mib != 106)
		{
			uint8_t mibl = available_size(mibstr.mib);
			if (mibl <= 2) mibl = 0b01;
			else if (mibl <= 4) mibl = 0b10;
			else if (mibl <= 8) mibl = 0b11;
			tag |= mibl << 3;
		}
		uint64_t size = mibstr.string.size();
		uint8_t llen = available_size(size);
		tag |= llen - 1;
		result.push_back(tag);
		for (uint8_t i = 0; i < llen; ++i)
		{
			result.push_back(pick_byte(size, llen - i - 1));
		}
		for (uint64_t i = 0; i < size; ++i)
		{
			result.push_back(mibstr.string[i]);
		}
	}
	else if (this->value_.index() == 6)
	{
		tag = 0b11000000;
		auto value = this->to_array();
		uint64_t size = value.size();
		uint8_t llen = available_size(size);
		tag |= llen - 1;
		result.push_back(tag);
		for (uint8_t i = 0; i < llen; ++i)
		{
			result.push_back(pick_byte(size, llen - i - 1));
		}
		for (uint64_t i = 0; i < size; ++i)
		{
			auto vbs = value[i].serialize();
			result.insert(result.end(), vbs.begin(), vbs.end());
		}
	}
	else if (this->value_.index() == 7)
	{
		tag = 0b11001000;
		auto value = this->to_set();
		uint64_t size = value.size();
		uint8_t llen = available_size(size);
		tag |= llen - 1;
		result.push_back(tag);
		for (uint8_t i = 0; i < llen; ++i)
		{
			result.push_back(pick_byte(size, llen - i - 1));
		}
		for (const auto& key : value)
		{
			auto vbs = key.serialize();
			result.insert(result.end(), vbs.begin(), vbs.end());
		}

	}
	else if (this->value_.index() == 8)
	{
		tag = 0b11101000;
		auto value = this->to_enum();
		uint64_t size = value.size();
		uint8_t llen = available_size(size);
		tag |= llen - 1;
		result.push_back(tag);
		for (uint8_t i = 0; i < llen; ++i)
		{
			result.push_back(pick_byte(size, llen - i - 1));
		}
		for (const auto& [key, val] : value)
		{
			tag = 0b01000000;
			char sign = key.sign >= 0 ? 0 : 1;
			tag |= sign << 3;
			uint8_t len = available_size(key.number);
			tag |= len;
			result.push_back(tag);
			for (uint8_t i = 0; i < len; ++i)
			{
				result.push_back(pick_byte(key.number, len - i - 1));
			}
			auto vbs = val.serialize();
			result.insert(result.end(), vbs.begin(), vbs.end());
		}
	}
	else if (this->value_.index() == 9)
	{
		tag = 0b11010000;
		auto value = this->to_map();
		uint64_t size = value.size();
		uint8_t llen = available_size(size);
		tag |= llen - 1;
		result.push_back(tag);
		for (uint8_t i = 0; i < llen; ++i)
		{
			result.push_back(pick_byte(size, llen - i - 1));
		}
		for (const auto& [key, val] : value)
		{
			auto vbs = key.serialize();
			result.insert(result.end(), vbs.begin(), vbs.end());
			vbs = val.serialize();
			result.insert(result.end(), vbs.begin(), vbs.end());
		}
	}
	else if (this->value_.index() == 10)
	{
		tag = 0b11011000;
		auto value = this->to_object();
		uint64_t size = value.size();
		uint8_t llen = available_size(size);
		tag |= llen - 1;
		result.push_back(tag);
		for (uint8_t i = 0; i < llen; ++i)
		{
			result.push_back(pick_byte(size, llen - i - 1));
		}
		for (const auto& [key, val] : value)
		{
			tag = 0b10100000;
			//
			if (key.mib != 106)
			{
				uint8_t mibl = available_size(key.mib);
				if (mibl <= 2) mibl = 0b01;
				else if (mibl <= 4) mibl = 0b10;
				else if (mibl <= 8) mibl = 0b11;
				tag |= mibl << 3;
			}
			uint64_t size = key.string.size();
			uint8_t llen = available_size(size);
			tag |= llen - 1;
			result.push_back(tag);
			for (uint8_t i = 0; i < llen; ++i)
			{
				result.push_back(pick_byte(size, llen - i - 1));
			}
			for (uint64_t i = 0; i < size; ++i)
			{
				result.push_back(key.string[i]);
			}
			auto vbs = val.serialize();
			result.insert(result.end(), vbs.begin(), vbs.end());
		}
	}
	return result;
}

#undef NSROOT
