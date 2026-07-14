#pragma once
#include "export.h"

#include <iostream>
#include <functional>
#include <random>

#include "serialize/serialize.h"
#include "crypto/sym/sym_base.h"
#include "crypto/sym/block/sym_block_base.h"

namespace dog_torch::crypto::sym::block::padding
{
	struct DOG_TORCH_API ISO10126 : public Padding
	{
		static void padding(BinaryData& data, uint64_t block_size);
		static void unpadding(BinaryData& data, uint64_t block_size);

		static const Config& allowed_config();

		Config config() const override;
		std::unique_ptr<Padding> clone() const override;
		std::string fmt_string() const override;
		bool check(uint64_t block_size) const override;
		padding_func get_padding() const override;
		padding_func get_unpadding() const override;
	};
}