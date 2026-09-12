#pragma once
#include "export.h"

#include <iostream>
#include <functional>

#include "utils/compile.h"
#include "serialize/serialize.h"
#include "crypto/sym/sym_base.h"
#include "crypto/sym/block/sym_block_base.h"

namespace dog_torch::crypto::sym::block::algorithm
{
    struct CPP_API Camellia : public Algorithm
    {
		Camellia(uint64_t key_size);
		~Camellia() override = default;

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

		static const uint8_t Sbox[256];
		static const uint64_t sigma[6];
		static std::pair<uint64_t, uint64_t> ui128rotl(uint64_t l, uint64_t r, uint64_t i);
		static uint8_t s1(uint8_t n);
		static uint8_t s2(uint8_t n);
		static uint8_t s3(uint8_t n);
		static uint8_t s4(uint8_t n);

		static uint64_t s(uint64_t n);
		static uint64_t p(uint64_t n);
		static uint64_t FL(uint64_t x, uint64_t kl);
		static uint64_t FL_inv(uint64_t y, uint64_t kl);
		static uint64_t F(uint64_t x, uint64_t k);

		static BinaryData extend_key(const BinaryData& key, uint64_t block_size, uint64_t key_size);

		static BinaryData encoding(const BinaryData& plain, uint64_t block_size, const BinaryData& key, uint64_t key_size);
		static BinaryData decoding(const BinaryData& crypt, uint64_t block_size, const BinaryData& key, uint64_t key_size);

		static void encoding_self(BinaryData& plain, uint64_t block_size, const BinaryData& key, uint64_t key_size);
		static void decoding_self(BinaryData& crypt, uint64_t block_size, const BinaryData& key, uint64_t key_size);
    };
}