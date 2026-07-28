#include "serialize/asn1.h"

namespace NSROOT = dog_torch::serialize::asn1;

NSROOT::Value::Value(const Value& other)
{
	this->value_ = other.value_;
}
NSROOT::Value NSROOT::Value::operator=(const Value& other)
{
	this->value_ = other.value_;
	return *this;
}
NSROOT::Value::Value(Value&& other) noexcept
{
	this->value_ = std::move(other.value_);
}
NSROOT::Value& NSROOT::Value::operator=(Value&& other) noexcept
{
	if (this == &other) return *this;
	this->value_ = std::move(other.value_);
	return *this;
}
NSROOT::Value::Value(bool value)
{
	this->value_ = value;
}
NSROOT::Value::Value(const BigInteger& value)
{
	this->value_ = value;
}
NSROOT::Value::Value(const std::vector<NSROOT::Value>& value)
{
	this->value_ = value;
}
NSROOT::Type NSROOT::Value::type() const
{
	return static_cast<Type>(this->value_.index());
}
const bool& NSROOT::Value::to_bool() const
{
	return std::get<bool>(this->value_);
}
bool& NSROOT::Value::to_bool()
{
	return std::get<bool>(this->value_);
}

const NSROOT::Value::BigInteger& NSROOT::Value::to_integer() const
{
	return std::get<BigInteger>(this->value_);
}
NSROOT::Value::BigInteger& NSROOT::Value::to_integer()
{
	return std::get<BigInteger>(this->value_);
}

const std::vector<NSROOT::Value>& NSROOT::Value::to_sequence() const
{
	return std::get<std::vector<NSROOT::Value>>(this->value_);
}
std::vector<NSROOT::Value>& NSROOT::Value::to_sequence()
{
	return std::get<std::vector<NSROOT::Value>>(this->value_);
}

uint64_t get_length(std::function<uint8_t()> next)
{
	uint8_t tag = next();
	if (tag < 0x80)
	{
		return tag;
	}
	uint64_t length = 0;
	uint8_t llen = tag & 0x7F;
	for (uint8_t i = 0; i < llen; i++)
	{
		length = (length << 8) | next();
	}
	return length;
}

NSROOT::Value NSROOT::Value::parse(std::vector<uint8_t>::const_iterator& pos, std::vector<uint8_t>::const_iterator end)
{
	auto next = [&pos]()->uint8_t
		{
			return *(pos++);
		};
	uint64_t type = next();
	if (type == 0x01)//NSROOT::Type::Bool
	{
		uint8_t llen = next();
		uint8_t value = next();
		if (llen != 1)
		{
			throw DOG_EXCEPTION("asn1: bool length error");
		}
		return NSROOT::Value(value != 0x00);
	}
	else if (type == 0x02)
	{
		uint64_t length = get_length(next);
		std::vector<uint8_t> bytes;
		for (uint64_t i = 0; i < length; i++)
		{
			bytes.push_back(next());
		}
		namespace Number = dog_torch::math::number;
		Number::BigUnsignedInteger biguint = Number::BigUnsignedInteger::from_bytes(bytes, false);
		char sign = (bytes[0] & 0x80) ? -1 : 1;
		if (sign == -1)
		{
			biguint = ~biguint + 1;
		}
		return NSROOT::Value(Number::BigInteger(sign, biguint));
	}
	else if (type == 0x30)
	{
		uint64_t length = get_length(next);
		std::vector<Value> values;
		while (length > 0)
		{
			auto now = pos;
			values.push_back(NSROOT::Value::parse(pos, end));
			length -= std::distance(now, pos);
		}
		return NSROOT::Value(values);
	}
}
NSROOT::Value NSROOT::Value::parse(std::istream& input, uint64_t* const len)
{
	auto next = [&input, len]()->uint8_t
		{
			if (len) (*len)++;
			return input.get();
		};
	uint64_t type = next();
	if (type == 0x01)//NSROOT::Type::Bool
	{
		uint8_t llen = next();
		uint8_t value = next();
		if (llen != 1)
		{
			throw DOG_EXCEPTION("asn1: bool length error");
		}
		return NSROOT::Value(value != 0x00);
	}
	else if (type == 0x02)
	{
		uint64_t length = get_length(next);
		std::vector<uint8_t> bytes;
		for (uint64_t i = 0; i < length; i++)
		{
			bytes.push_back(next());
		}
		namespace Number = dog_torch::math::number;
		Number::BigUnsignedInteger biguint = Number::BigUnsignedInteger::from_bytes(bytes, false);
		char sign = (bytes[0] & 0x80) ? -1 : 1;
		if (sign == -1)
		{
			biguint = ~biguint + 1;
		}
		return NSROOT::Value(Number::BigInteger(sign, biguint));
	}
	else if (type == 0x30)
	{
		uint64_t length = get_length(next);
		std::vector<Value> values;
		while (length > 0)
		{
			uint64_t size = 0;
			values.push_back(NSROOT::Value::parse(input, &size));
			length -= size;
		}
		return NSROOT::Value(values);
	}
}

std::vector<uint8_t> fmt_len(uint64_t size)
{
	if (size < 128)
	{
		return std::vector<uint8_t>{ static_cast<uint8_t>(size) };
	}
	else
	{
		std::vector<uint8_t> result;
		namespace Integer = dog_torch::math::integer;
		uint8_t llen = Integer::available_size(size);
		result.push_back(llen | 0x80);
		for (uint8_t i = llen - 1; ; i--)
		{
			result.push_back(size >> (i * 8));
			if (i == 0) break;
		}
		return result;
	}
}

std::vector<uint8_t> NSROOT::Value::serialize() const
{
	uint64_t type = this->value_.index();
	std::vector<uint8_t> result;
	if (type == 0)//NSROOT::Type::Bool
	{
		result.push_back(0x01);//tag
		result.push_back(0x01);//length
		result.push_back(std::get<bool>(this->value_) ? 0xFF : 0x00);
	}
	else if (type == 1)//NSROOT::Type::Integer
	{
		namespace Number = dog_torch::math::number;
		result.push_back(0x02);//tag
		Number::BigInteger bigint = std::get<Number::BigInteger>(this->value_);
		std::vector<uint8_t> bytes;
		if (bigint.sign_ > -1)
		{
			bytes = bigint.num_.to_bytes(false);
			if (bytes[0] >= 0x80)
			{
				bytes.insert(bytes.begin(), 0x00);
			}
		}
		else
		{
			Number::BigUnsignedInteger biguint = bigint.num_;
			biguint = ~biguint + 1;
			bytes = biguint.to_bytes(false);
		}
		auto temp = fmt_len(bytes.size());
		result.insert(result.end(), temp.begin(), temp.end());
		result.insert(result.end(), bytes.begin(), bytes.end());
	}
	else if (type == 2)//NSROOT::Type::Sequence
	{
		result.push_back(0x30);//tag
		std::vector<uint8_t> bytes;
		for (const auto& value : std::get<std::vector<Value>>(this->value_))
		{
			auto temp = value.serialize();
			bytes.insert(bytes.end(), temp.begin(), temp.end());
		}
		auto len_v = fmt_len(bytes.size());
		result.insert(result.end(), len_v.begin(), len_v.end());
		result.insert(result.end(), bytes.begin(), bytes.end());
	}
	return result;
}