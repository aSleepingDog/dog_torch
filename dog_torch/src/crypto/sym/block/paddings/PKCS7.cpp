#include "crypto/sym/block/paddings/PKCS7.h"
#include "error_msg.h"

namespace NSROOT = dog_torch::crypto::sym::block::padding;

void NSROOT::PKCS7::padding(BinaryData& data, uint64_t block_size)
{
	if (block_size == 0 || block_size > 0xff)
		throw DOG_EXCEPTION(array_to_view(ERROR_PKCS7_SIZE_WRONG));
	uint8_t fill = static_cast<uint8_t>(block_size - data.size());
	while (data.size() < block_size) data.push_back(fill);
}
void NSROOT::PKCS7::unpadding(BinaryData& data, uint64_t block_size)
{
	if (block_size == 0 || block_size > 0xff)
		throw DOG_EXCEPTION(array_to_view(ERROR_PKCS7_BLOCK_WRONG));
	if (data.size() != block_size)
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_PKCS7_BLOCK_WRONG));
	}
	uint8_t unfill = data.back();
	if (unfill == 0 || unfill > block_size)
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_PKCS7_BLOCK_WRONG));
	}
	volatile uint64_t x = 0;
	for (uint64_t i = 0; i < block_size; ++i)
	{
		if (i < block_size - unfill)
		{
			x |= 0;
		}
		else
		{
			x |= unfill;
		}
	}
	if (x != 0)
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_PKCS7_BLOCK_WRONG));
	}
	data.resize(data.size() - unfill);
}
const NSROOT::Config& NSROOT::PKCS7::allowed_config()
{
	static Config config = Config("PKCS7", "[1,255|1]");
	return config;
}
NSROOT::Config NSROOT::PKCS7::config() const
{
	return PKCS7::allowed_config();
}
std::unique_ptr<NSROOT::Padding> NSROOT::PKCS7::clone() const
{
	return std::make_unique<PKCS7>(*this);
}
std::string NSROOT::PKCS7::fmt_string() const
{
	return allowed_config().name;
}
bool NSROOT::PKCS7::check(uint64_t block_size) const
{
	return block_size >= 1 && block_size <= 255;
}
NSROOT::padding_func NSROOT::PKCS7::get_padding() const
{
	return PKCS7::padding;
}
NSROOT::padding_func NSROOT::PKCS7::get_unpadding() const
{
	return PKCS7::unpadding;
}

#undef NSROOT
