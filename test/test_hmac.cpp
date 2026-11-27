#include "crypto/hash/algorithms/SHA2.h"
#include "crypto/mac/hmac_base.h"

using dog_torch::serialize::BinaryData;
using dog_torch::crypto::hash::algorithm::SHA2;
using dog_torch::crypto::hash::Generator;
using dog_torch::crypto::mac::HMacGenerator;

void output(const BinaryData& key, const BinaryData& data, 
	const HMacGenerator& gen0, const BinaryData& out0, const BinaryData& right0,
	const HMacGenerator& gen1, const BinaryData& out1, const BinaryData& right1,
	const HMacGenerator& gen2, const BinaryData& out2, const BinaryData& right2,
	const HMacGenerator& gen3, const BinaryData& out3, const BinaryData& right3)
{
	std::cout << "[key]" << std::endl;
	std::cout << key.to_hex_string(true) << ":Hex:upper" << std::endl;
	std::cout << "[data]" << std::endl;
	std::cout << data.to_hex_string(true) << ":Hex:upper" << std::endl;

	std::cout << "[operator]" << std::endl;
	std::cout << gen0.fmt_string() << std::endl;
	std::cout << "[output]" << std::endl;
	std::cout << out0.to_hex_string(true) << ":Hex:upper" << std::endl;
	std::cout << "[right]" << std::endl;
	std::cout << right0.to_hex_string(true) << ":Hex:upper" << std::endl;
	
	std::cout << "[operator]" << std::endl;
	std::cout << gen1.fmt_string() << std::endl;
	std::cout << "[output]" << std::endl;
	std::cout << out1.to_hex_string(true) << ":Hex:upper" << std::endl;
	std::cout << "[right]" << std::endl;
	std::cout << right1.to_hex_string(true) << ":Hex:upper" << std::endl;

	std::cout << "[operator]" << std::endl;
	std::cout << gen2.fmt_string() << std::endl;
	std::cout << "[output]" << std::endl;
	std::cout << out2.to_hex_string(true) << ":Hex:upper" << std::endl;
	std::cout << "[right]" << std::endl;
	std::cout << right2.to_hex_string(true) << ":Hex:upper" << std::endl;

	std::cout << "[operator]" << std::endl;
	std::cout << gen3.fmt_string() << std::endl;
	std::cout << "[output]" << std::endl;
	std::cout << out3.to_hex_string(true) << ":Hex:upper" << std::endl;
	std::cout << "[right]" << std::endl;
	std::cout << right3.to_hex_string(true) << ":Hex:upper" << std::endl;

	std::cout << std::endl;
}
uint64_t error = 0;
void work(const std::string& key, const std::string& data,
	const std::string& right0, const std::string& right1,
	const std::string& right2, const std::string& right3)
{
	HMacGenerator gen0 = HMacGenerator(BinaryData{ key,BinaryData::Type::Hex }, SHA2(224).clone());
	gen0.set_key(BinaryData{ key,BinaryData::Type::Hex });
	auto r0 = gen0.generate(BinaryData{ data,BinaryData::Type::Hex });
	if (r0 != BinaryData{ right0,BinaryData::Type::Hex }) error++;

	HMacGenerator gen1 = HMacGenerator(BinaryData{ key,BinaryData::Type::Hex }, SHA2(256).clone());
	gen1.set_key(BinaryData{ key,BinaryData::Type::Hex });
	auto r1 = gen1.generate(BinaryData{ data,BinaryData::Type::Hex });
	if (r1 != BinaryData{ right1,BinaryData::Type::Hex }) error++;

	HMacGenerator gen2 = HMacGenerator(BinaryData{ key,BinaryData::Type::Hex }, SHA2(384).clone());
	gen2.set_key(BinaryData{ key,BinaryData::Type::Hex });
	auto r2 = gen2.generate(BinaryData{ data,BinaryData::Type::Hex });
	if (r2 != BinaryData{ right2,BinaryData::Type::Hex }) error++;

	HMacGenerator gen3 = HMacGenerator(BinaryData{ key,BinaryData::Type::Hex }, SHA2(512).clone());
	gen3.set_key(BinaryData{ key,BinaryData::Type::Hex });
	auto r3 = gen3.generate(BinaryData{ data,BinaryData::Type::Hex });
	if (r3 != BinaryData{ right3,BinaryData::Type::Hex }) error++;

	output(BinaryData{ key,BinaryData::Type::Hex }, BinaryData{ data,BinaryData::Type::Hex },
		gen0, r0, BinaryData{ right0,BinaryData::Type::Hex },
		gen1, r1, BinaryData{ right1,BinaryData::Type::Hex },
		gen2, r2, BinaryData{ right2,BinaryData::Type::Hex },
		gen3, r3, BinaryData{ right3,BinaryData::Type::Hex }
	);
}
int main()
{
	std::cout << "test set from " << R"<url>(https://www.rfc-editor.org/info/rfc4231/)<url>" << std::endl;

	work(
		"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", 
		"4869205468657265",
		"896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
		"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
		"afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
		"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
	);
	work(
		"4a656665",
		"7768617420646f2079612077616e7420666f72206e6f7468696e673f",
		"a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
		"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
		"af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
		"164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
	);
	work(
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		"7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
		"773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
		"88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
		"fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");
	work(
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 
		"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
		"95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
		"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
		"4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
		"80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598");
	work(
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
		"3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
		"9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
		"6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
		"e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58");
	std::cout << "error:" << error << std::endl;
}