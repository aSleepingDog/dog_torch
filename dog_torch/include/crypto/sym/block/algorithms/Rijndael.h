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
	struct Rijndael
	{
		static const uint8_t SBox[16][16];
		static const uint8_t InvSBox[16][16];
		static const uint8_t MixTable[16];
		static const uint8_t UMixTable[16];
		static const uint8_t round[16];
		static uint8_t Xtime(uint8_t a, uint8_t b);
	};

    struct DOG_TORCH_API AES : public Algorithm
    {
        AES(uint64_t key_size);
        ~AES() override = default;

		static const Config& allowed_config();
		Config config() const override;
		std::unique_ptr<Algorithm> clone() const override;
		std::string fmt_string() const override;

		extend_key_func get_extend_key() const override;
		block_cryption_func get_encrypt() const override;
		block_cryption_func get_decrypt() const override;
		block_self_cryption_func get_encrypt_self() const override;
		block_self_cryption_func get_decrypt_self() const override;

		static void middle_encryption(BinaryData& datablock, uint64_t flag, uint64_t mode);
		static void middle_decryption(BinaryData& datablock, uint64_t flag, uint64_t mode);

		static BinaryData extend_key(const BinaryData& key, uint64_t block_size, uint64_t key_size);

		static BinaryData encoding(const BinaryData& plain, uint64_t block_size, const BinaryData& key, uint64_t key_size);
		static BinaryData decoding(const BinaryData& crypt, uint64_t block_size, const BinaryData& key, uint64_t key_size);

		static void encoding_self(BinaryData& plain, uint64_t block_size, const BinaryData& key, uint64_t key_size);
		static void decoding_self(BinaryData& crypt, uint64_t block_size, const BinaryData& key, uint64_t key_size);
    };
}