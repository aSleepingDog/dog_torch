#include "crypto/sym/block/paddings/ANSIX923.h"
#include "error_msg.h"

namespace NSROOT = dog_torch::crypto::sym::block::padding;

void NSROOT::ANSIX923::padding(BinaryData& data, uint64_t block_size)
{
	if (block_size == 0 || block_size > 0xff)
		throw DOG_EXCEPTION(array_to_view(ERROR_PKCS7_SIZE_WRONG));
	uint8_t fill = static_cast<uint8_t>(block_size - data.size());
	data.resize(block_size);
	data.back() = fill;
}
void NSROOT::ANSIX923::unpadding(BinaryData& data, uint64_t block_size)
{
	if (block_size == 0 || block_size > 0xff)
		throw DOG_EXCEPTION(array_to_view(ERROR_ANSIX923_SIZE_WRONG));
	if (data.size() != block_size)
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_ANSIX923_BLOCK_WRONG));
	}
	uint8_t unfill = data.back();
	if (unfill == 0 || unfill > block_size)
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_ANSIX923_BLOCK_WRONG));
	}
	volatile uint8_t x = 0;
	for (uint64_t i = 0; i < block_size; ++i)
	{
		if (i < block_size - unfill)
		{
			x |= 0;
		}
		else if (i != block_size - 1)
		{
			x |= data[i];
		}
		else
		{
			x |= data[i] ^ unfill;
		}
	}
	if (x != 0)
	{
		throw DOG_EXCEPTION(array_to_view(ERROR_ANSIX923_BLOCK_WRONG));
	}
	data.resize(data.size() - unfill);
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
