#include "crypto/sym/block/paddings/ZERO.h"

namespace NSROOT = dog_torch::crypto::sym::block::padding;

void NSROOT::ZERO::padding(BinaryData& data, uint64_t block_size)
{
	data.resize(block_size, 0);
}
void NSROOT::ZERO::unpadding(BinaryData& data, uint64_t block_size)
{
	while (data.size() > 0 && data.back() == 0) data.pop_back();
}
const NSROOT::Config& NSROOT::ZERO::allowed_config()
{
	static Config config = Config("ZERO", "[1,18446744073709551615|1]");
	return config;
}
NSROOT::Config NSROOT::ZERO::config() const
{
	return ZERO::allowed_config();
}
std::unique_ptr<NSROOT::Padding> NSROOT::ZERO::clone() const
{
	return std::make_unique<ZERO>(*this);
}
std::string NSROOT::ZERO::fmt_string() const
{
	return allowed_config().name;
}
bool NSROOT::ZERO::check(uint64_t block_size) const
{
	return block_size >= 1;
}
NSROOT::padding_func NSROOT::ZERO::get_padding() const
{
	return ZERO::padding;
}
NSROOT::padding_func NSROOT::ZERO::get_unpadding() const
{
	return ZERO::unpadding;
}

#undef NSROOT
