#include "crypto/hash/algorithms/SM3.h"

using dog_torch::serialize::BinaryData;
using dog_torch::crypto::hash::algorithm::SM3;
using dog_torch::crypto::hash::Generator;

void output(const BinaryData& in, const Generator& gen, const BinaryData& out, const BinaryData& right)
{
	std::cout << "[input]" << std::endl;
	std::cout << in.to_string() << ":UTF8" << std::endl;
	std::cout << "[operator]" << std::endl;
	std::cout << gen.fmt_string() << std::endl;
	std::cout << "[output]" << std::endl;
	std::cout << out.to_hex_string(true) << ":Hex:upper" << std::endl;
	std::cout << "[right]" << std::endl;
	std::cout << right.to_hex_string(true) << ":Hex:upper" << std::endl;
	std::cout << std::endl;
}

int main()
{
	uint64_t error = 0;
	std::cout << "test set from " << R"<url>(GM/T0004-2012)<url>" << std::endl;
	{
		BinaryData i{ "abc",BinaryData::Type::UTF8 };
		auto gen = Generator(SM3());
		auto h = gen.calculate(i);
		BinaryData c{ "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",BinaryData::Type::Hex };
		output(i, gen, h, c);
		if (h != c) error++;
	}
	{
		BinaryData i{ "61626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364",BinaryData::Type::Hex };
		auto gen = Generator(SM3());
		auto h = gen.calculate(i);
		BinaryData c{ "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",BinaryData::Type::Hex };
		output(i, gen, h, c);
		if (h != c) error++;
	}
	std::cout << "error:" << error << std::endl;
}
