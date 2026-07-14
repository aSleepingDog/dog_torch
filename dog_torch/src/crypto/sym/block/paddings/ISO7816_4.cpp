#include "crypto/sym/block/paddings/ISO7816_4.h"

namespace NSROOT = dog_torch::crypto::sym::block::padding;

void NSROOT::ISO7816_4::padding(BinaryData& data, uint64_t block_size)
{
	data.push_back(0x80);
	data.resize(block_size, 0);
}
void NSROOT::ISO7816_4::unpadding(BinaryData& data, uint64_t block_size)
{
	while (data.size() > 0 && data.back() == 0x00) data.pop_back();
	if(data.size() > 0 && data.back() == 0x80) data.pop_back();
}
const NSROOT::Config& NSROOT::ISO7816_4::allowed_config()
{
	static Config config = Config("ISO7816_4", "[1,18446744073709551615|1]");
	return config;
}
NSROOT::Config NSROOT::ISO7816_4::config() const
{
	return ISO7816_4::allowed_config();
}
std::unique_ptr<NSROOT::Padding> NSROOT::ISO7816_4::clone() const
{
	return std::make_unique<ISO7816_4>(*this);
}
std::string NSROOT::ISO7816_4::fmt_string() const
{
	return allowed_config().name;
}
bool NSROOT::ISO7816_4::check(uint64_t block_size) const
{
	return block_size >= 1 && block_size <= 255;
}
NSROOT::padding_func NSROOT::ISO7816_4::get_padding() const
{
	return ISO7816_4::padding;
}
NSROOT::padding_func NSROOT::ISO7816_4::get_unpadding() const
{
	return ISO7816_4::unpadding;
}

#undef NSROOT
