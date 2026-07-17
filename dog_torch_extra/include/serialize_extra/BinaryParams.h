#pragma once
#include "export.h"

#include <variant>

#include "serialize/BinaryData.h"

namespace dog_torch::serialize
{
	enum class Type : uint64_t
	{
		UTF_8 = 0,
		Binary = 1,
		Hex = 2,
		Base64 = 3,
	};

	std::string type_fmt_string(Type type);

	class BinaryParams
	{
		using Param = std::variant<bool, char>;
	private:
		Type type_;
		std::vector<Param> params_;
	public:
		BinaryParams() = default;

		static BinaryParams from_utf8();
		static BinaryParams from_binary();
		static BinaryParams from_hex(bool is_upper);
		static BinaryParams from_base64(char a = '+', char b = '/', char c = '=');

		std::string fmt_BinaryData(const BinaryData& data);
		std::string fmt_string();
	};
}