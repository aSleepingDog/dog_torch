#pragma once
#include "export.h"

#include <set>
#include <map>
#include <stack>
#include <vector>
#include <string>
#include <cstring>
#include <variant>
#include <iostream>
#include <unordered_map>
#include <unordered_set>

#include "utils/compile.h"
#include "BinaryData.h"
#include "math/number.h"
#include "math/integer.h"
#include "utils/exception.h"

namespace dog_torch::serialize::tlv
{
	struct CPP_API MIBString
	{
		//define in https://www.iana.org/assignments/character-sets
		uint64_t mib;//utf-8 = 106
		std::string string;

		MIBString(const std::string& str, uint64_t mid = 106);
		MIBString(std::string&& str, uint64_t mid = 106);
		MIBString(const std::u8string& str);
		bool operator==(const MIBString& other) const;
	};

	class CPP_API Value;

}
namespace std
{
	template<>
	struct CPP_API hash<dog_torch::serialize::tlv::MIBString>
	{
		size_t operator()(const dog_torch::serialize::tlv::MIBString& value) const;
	};

	template<>
	struct CPP_API hash<dog_torch::serialize::tlv::Value>
	{
		size_t operator()(const dog_torch::serialize::tlv::Value& value_) const;
	};
}
/*
* TLV value
* other0  0000 XXXX                                                     -- 0X
* other1  0001 XXXX                                                     -- 1X
* null    0010 0000                                                     -- 2X     0
* bool    0011 0000/false 1111/true                                     -- 3X     1
* u/int   010 0 0+/1- LLL                                               -- 4X     2
* float   011 000 00-16 01-32 10-64 11-128                              -- 6X     3
* binary  100 0 0 LLL                                                   -- 8X     4
* string  101 00-utf8/01-2BMiB/10-4BMIB/11-8BMIB LLL (2-4) uint         -- AX     5
* container   11 XXX LLL
* 000 - array  - TL V|TL V                                              -- C >=8  6
* 001 - set    - TL V|TL V                                              -- C < 8  7
* 101 - enum   - u/int,TL V|u/int,TL V                                  -- E >=8  8
* 010 - map    - TL V,TL V|TL V,TL V                                    -- D < 8  9
* 011 - object - string,TL V|string,TL V                                -- D >=8  10
*/
namespace dog_torch::serialize::tlv
{
	enum class CPP_API Type : uint8_t
	{
		Null = 0,
		Bool = 1,
		Integer = 2,
		Float = 3,
		Binary = 4,
		String = 5,
		Array = 6,
		Set = 7,
		Enum = 8,
		Map = 9,
		Object = 10
	};

	using Integer64 = dog_torch::math::number::Integer64;

	class CPP_API Value
	{
	public:
		using _store = std::variant<
			std::nullptr_t,                        //0
			bool,                                  //1
			Integer64,                             //2
			double,                                //3
			std::vector<uint8_t>,                  //4
			MIBString,                             //5
			std::vector<Value>,                    //6
			std::unordered_set<Value>,             //7
			std::unordered_map<Integer64, Value>,  //8
			std::unordered_map<Value, Value>,      //9
			std::unordered_map<MIBString, Value>   //10
		>;
	private:
		_store value_;

	public:
		Value();
		Value(std::nullptr_t);
		Value(bool value);

		Value(const Integer64& value);
		Value(Integer64&& value);
		Value(char sign, uint64_t number);

		Value(double value);

		Value(const std::vector<uint8_t>& value);
		Value(std::vector<uint8_t>&& value);

		Value(const MIBString& value);
		Value(MIBString&& value);

		Value(const std::vector<Value>& value);
		Value(std::vector<Value>&& value);

		Value(const std::unordered_set<Value>& value);
		Value(std::unordered_set<Value>&& value);

		Value(const std::unordered_map<Integer64, Value>& value);
		Value(std::unordered_map<Integer64, Value>&& value);

		Value(const std::unordered_map<Value, Value>& value);
		Value(std::unordered_map<Value, Value>&& value);

		Value(const std::unordered_map<MIBString, Value>& value);
		Value(std::unordered_map<MIBString, Value>&& value);

		Value(const Value& other);
		Value& operator=(const Value& other);
		Value(Value&& other) noexcept;
		Value& operator=(Value&& other) noexcept;

		const _store& get() const;
		_store& get();

		bool operator==(const Value& other) const;

		Type type() const;

		std::nullptr_t to_null() const;
		
		bool& to_bool();
		bool to_bool() const;

		Integer64& to_integer();
		const Integer64& to_integer() const;

		double& to_float();
		double to_float() const;

		std::vector<uint8_t>& to_binary();
		const std::vector<uint8_t>& to_binary() const;

		MIBString& to_string();
		const MIBString& to_string() const;

		std::vector<Value>& to_array();
		const std::vector<Value>& to_array() const;

		std::unordered_set<Value>& to_set();
		const std::unordered_set<Value>& to_set() const;

		std::unordered_map<Integer64, Value>& to_enum();
		const std::unordered_map<Integer64, Value>& to_enum() const;

		std::unordered_map<Value, Value>& to_map();
		const std::unordered_map<Value, Value>& to_map() const;

		std::unordered_map<MIBString, Value>& to_object();
		const std::unordered_map<MIBString, Value> to_object() const;

		static Value parse(std::vector<uint8_t>::const_iterator& pos, std::vector<uint8_t>::const_iterator end);
		static Value parse(std::istream& input);

		std::vector<uint8_t> serialize() const;
		std::string fmt_string(uint64_t depth = 0, uint64_t count = 4, char fill = ' ') const;
	};
}

