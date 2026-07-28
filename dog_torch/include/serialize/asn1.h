#pragma once
#include "export.h"

#include <set>
#include <map>
#include <stack>
#include <vector>
#include <string>
#include <variant>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <functional>

#include "utils/compile.h"
#include "BinaryData.h"
#include "math/number.h"
#include "math/integer.h"
#include "utils/exception.h"

namespace dog_torch::serialize::asn1
{
	enum class CPP_API Type : uint8_t
	{
		Bool = 0,
		Integer = 1,
		Sequence = 48
	};

	class CPP_API Value
	{
		using BigInteger = dog_torch::math::number::BigInteger;
		std::variant<
			bool,
			BigInteger,
			std::vector<Value>
		> value_;
	public:
		Value(const Value& other);
		Value operator=(const Value& other);
		Value(Value&& other) noexcept;
		Value& operator=(Value&& other) noexcept;

		explicit Value(bool value);
		Value(const BigInteger& value);
		Value(const std::vector<Value>& value);

		Type type() const;

		const bool& to_bool() const;
		bool& to_bool();

		const BigInteger& to_integer() const;
		BigInteger& to_integer();

		const std::vector<Value>& to_sequence() const;
		std::vector<Value>& to_sequence();

		static Value parse(std::vector<uint8_t>::const_iterator& pos, std::vector<uint8_t>::const_iterator end);
		static Value parse(std::istream& input, uint64_t* const len = nullptr);

		std::vector<uint8_t> serialize() const;
	};
}