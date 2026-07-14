#include "crypto/sym/block/paddings/ISO10126.h"

namespace NSROOT = dog_torch::crypto::sym::block::padding;

void NSROOT::ISO10126::padding(BinaryData& data, uint64_t block_size)
{
	uint8_t fill = static_cast<uint8_t>(block_size - data.size());
	std::random_device rd;
	while (data.size() < block_size - 1)
		data.push_back(static_cast<uint8_t>(rd()));
	data.push_back(fill);
}
void NSROOT::ISO10126::unpadding(BinaryData& data, uint64_t block_size)
{
	uint8_t unfill = data.back();
	data.resize(data.size() >= unfill ? data.size() - unfill : data.size());
}
const NSROOT::Config& NSROOT::ISO10126::allowed_config()
{
	static Config config = Config("ISO10126", "[1,255|1]");
	return config;
}
NSROOT::Config NSROOT::ISO10126::config() const
{
	return ISO10126::allowed_config();
}
std::unique_ptr<NSROOT::Padding> NSROOT::ISO10126::clone() const
{
	return std::make_unique<ISO10126>(*this);
}
std::string NSROOT::ISO10126::fmt_string() const
{
	return allowed_config().name;
}
bool NSROOT::ISO10126::check(uint64_t block_size) const
{
	return block_size >= 1 && block_size <= 255;
}
NSROOT::padding_func NSROOT::ISO10126::get_padding() const
{
	return ISO10126::padding;
}
NSROOT::padding_func NSROOT::ISO10126::get_unpadding() const
{
	return ISO10126::unpadding;
}

#undef NSROOT
