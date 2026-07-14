#include "crypto/sym/block/paddings/ANSIX923.h"

namespace NSROOT = dog_torch::crypto::sym::block::padding;

void NSROOT::ANSIX923::padding(BinaryData& data, uint64_t block_size)
{
	uint8_t fill = static_cast<uint8_t>(block_size - data.size());
	while (data.size() < block_size - 1) data.push_back(0);
	data.push_back(fill);
}
void NSROOT::ANSIX923::unpadding(BinaryData& data, uint64_t block_size)
{
	uint8_t unfill = data.back();
	data.resize(data.size() >= unfill ? data.size() - unfill : data.size());
}
const NSROOT::Config& NSROOT::ANSIX923::allowed_config()
{
	static Config config = Config("ANSIX923", "[1,255|1]");
	return config;
}
NSROOT::Config NSROOT::ANSIX923::config() const
{
	return ANSIX923::allowed_config();
}
std::unique_ptr<NSROOT::Padding> NSROOT::ANSIX923::clone() const
{
	return std::make_unique<ANSIX923>(*this);
}
std::string NSROOT::ANSIX923::fmt_string() const
{
	return allowed_config().name;
}
bool NSROOT::ANSIX923::check(uint64_t block_size) const
{
	return block_size >= 1 && block_size <= 255;
}
NSROOT::padding_func NSROOT::ANSIX923::get_padding() const
{
	return ANSIX923::padding;
}
NSROOT::padding_func NSROOT::ANSIX923::get_unpadding() const
{
	return ANSIX923::unpadding;
}

#undef NSROOT
