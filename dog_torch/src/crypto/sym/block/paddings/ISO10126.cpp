#include "crypto/sym/block/paddings/ISO10126.h"
#include "error_msg.h"

namespace NSROOT = dog_torch::crypto::sym::block::padding;

void NSROOT::ISO10126::padding(BinaryData& data, uint64_t block_size)
{
	if (block_size == 0 || block_size > 0xff)
		throw DOG_EXCEPTION(array_to_view(ERROR_ISO10126_BLOCK_WRONG));
	if (data.size() == block_size) return;
	uint8_t fill = static_cast<uint8_t>(block_size - data.size());
	while (data.size() < block_size - 1)
		data.push_back(static_cast<uint8_t>(dog_torch::math::random::random_uint64()));
	data.push_back(fill);
}
void NSROOT::ISO10126::unpadding(BinaryData& data, uint64_t block_size)
{
	if (block_size == 0 || block_size > 0xff)
		throw DOG_EXCEPTION(array_to_view(ERROR_ISO10126_SIZE_WRONG));
	if (data.size() != block_size)
		throw DOG_EXCEPTION(array_to_view(ERROR_ISO10126_BLOCK_WRONG));
	uint8_t unfill = data.back();
	if (unfill == 0 || unfill > block_size)
		throw DOG_EXCEPTION(array_to_view(ERROR_ISO10126_BLOCK_WRONG));
	data.resize(data.size() - unfill);
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
