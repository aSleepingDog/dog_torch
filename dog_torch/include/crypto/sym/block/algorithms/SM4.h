#pragma once
#include "export.h"

#include <iostream>
#include <functional>

#include "serialize/serialize.h"
#include "crypto/sym/sym_base.h"
#include "crypto/sym/block/sym_block_base.h"

namespace dog_torch::crypto::sym::block::algorithm
{
    struct DOG_TORCH_API SM4 : public Algorithm
    {
		SM4();
		~SM4() override = default;

		static const Config& allowed_config();
		Config config() const override;
		std::unique_ptr<Algorithm> clone() const override;
		std::string fmt_string() const override;

		extend_key_func get_extend_key() const override;
		block_cryption_func get_encrypt() const override;
		block_cryption_func get_decrypt() const override;
		block_self_cryption_func get_encrypt_self() const override;
		block_self_cryption_func get_decrypt_self() const override;

		//具体实现
		static const uint8_t SBox[16][16];

		static const uint32_t FK[4];
		static const uint32_t CK[32];

		static uint32_t TMixChange1(uint32_t n);
		static uint32_t TMixChange2(uint32_t n);

		static BinaryData extend_key(const BinaryData& key, uint64_t block_size, uint64_t key_size);

		static BinaryData encoding(const BinaryData& plain, uint64_t block_size, const BinaryData& key, uint64_t key_size);
		static BinaryData decoding(const BinaryData& crypt, uint64_t block_size, const BinaryData& key, uint64_t key_size);

		static void encoding_self(BinaryData& plain, uint64_t block_size, const BinaryData& key, uint64_t key_size);
		static void decoding_self(BinaryData& crypt, uint64_t block_size, const BinaryData& key, uint64_t key_size);
    };
}