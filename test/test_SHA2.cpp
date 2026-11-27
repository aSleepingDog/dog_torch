#include "crypto/hash/algorithms/SHA2.h"

using dog_torch::serialize::BinaryData;
using dog_torch::crypto::hash::algorithm::SHA2;
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

	std::cout << "test set from " << R"<url>(https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values)<url>" << std::endl;
	{
		BinaryData i{ "abc",BinaryData::Type::UTF8 };
		auto gen = Generator(SHA2(256));
		auto h = gen.calculate(i);
		BinaryData c{ "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",BinaryData::Type::Hex };
		output(i, gen, h, c);
		if (h != c) error++;
	}
	{
		BinaryData i{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",BinaryData::Type::UTF8 };
		auto gen = Generator(SHA2(256));
		auto h = gen.calculate(i);
		BinaryData c{ "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1",BinaryData::Type::Hex };
		output(i, gen, h, c);
		if (h != c) error++;
	}
	{
		BinaryData i{ "abc",BinaryData::Type::UTF8 };
		auto gen = Generator(SHA2(224));
		auto h = gen.calculate(i);
		BinaryData c{ "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7",BinaryData::Type::Hex };
		output(i, gen, h, c);
		if (h != c) error++;
	}
	{
		BinaryData i{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",BinaryData::Type::UTF8 };
		auto gen = Generator(SHA2(224));
		auto h = gen.calculate(i);
		BinaryData c{ "75388B16512776CC5DBA5DA1FD890150B0C6455CB4F58B1952522525",BinaryData::Type::Hex };
		output(i, gen, h, c);
		if (h != c) error++;
	}
	{
		BinaryData i{ "abc",BinaryData::Type::UTF8 };
		auto gen = Generator(SHA2(384));
		auto h = gen.calculate(i);
		BinaryData c{ "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7",BinaryData::Type::Hex };
		output(i, gen, h, c);
		if (h != c) error++;
	}
	{
		BinaryData i{ "abc",BinaryData::Type::UTF8 };
		auto gen = Generator(SHA2(512));
		auto h = gen.calculate(i);
		BinaryData c{ "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F",BinaryData::Type::Hex };
		output(i, gen, h, c);
		if (h != c) error++;
	}
	{
		BinaryData i{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",BinaryData::Type::UTF8 };
		auto gen = Generator(SHA2(512));
		auto h = gen.calculate(i);
		BinaryData c{ "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909",BinaryData::Type::Hex };
		output(i, gen, h, c);
		if (h != c) error++;
	}
	std::cout << "error:" << error << std::endl;
}