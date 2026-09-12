#pragma once
#include "export.h"

#include <iostream>
#include <functional>

#include "serialize/serialize.h"
#include "utils/compile.h"
#include "crypto/sym/sym_base.h"
#include "crypto/sym/block/sym_block_base.h"

namespace dog_torch::crypto::sym::block::algorithm
{
	struct CPP_API Twofish : public Algorithm
	{
		Twofish(uint64_t key_size);
		~Twofish() override = default;

		static const Config& allowed_config();
		Config config() const override;
		std::unique_ptr<Algorithm> clone() const override;
		std::string fmt_string() const override;

		uint64_t get_block_size() const override;

		extend_key_func get_extend_key() const override;
		block_cryption_func get_encrypt() const override;
		block_cryption_func get_decrypt() const override;
		block_self_cryption_func get_encrypt_self() const override;
		block_self_cryption_func get_decrypt_self() const override;


		static const uint8_t P8x8[2][256];

		static const uint8_t GF14D[255];
		static const uint8_t GFi14D[255];
		static uint8_t mult14D(uint8_t a, uint8_t b);

		static uint8_t mult169(uint8_t a, uint8_t b);

		static const uint8_t MDS[16];
		static const uint8_t RS[32];

		static uint32_t multMDS(uint32_t n);
		static uint32_t multRS(uint64_t n);
		static uint32_t f_h(uint32_t x, std::vector<uint32_t> l);
		static BinaryData extend_key(const BinaryData& key, uint64_t block_size, uint64_t key_size);

		static BinaryData encoding(const BinaryData& plain, uint64_t block_size, const BinaryData& key, uint64_t key_size);
		static BinaryData decoding(const BinaryData& crypt, uint64_t block_size, const BinaryData& key, uint64_t key_size);

		static void encoding_self(BinaryData& plain, uint64_t block_size, const BinaryData& key, uint64_t key_size);
		static void decoding_self(BinaryData& crypt, uint64_t block_size, const BinaryData& key, uint64_t key_size);
	};
}