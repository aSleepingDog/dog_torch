#pragma once
#include "export.h"

#include "utils/compile.h"
#include "math/math.h"
#include "serialize/serialize.h"
#include "crypto/hash/hash_algorithms.h"
#include "crypto/asym/asym_base.h"

namespace dog_torch::crypto::asym::algorithm
{
	class RSA : public Algorithm
	{
	private:
		uint32_t public_key_;
	public:
		RSA(uint64_t key_size, uint32_t public_key);

		static KeyPair create_key_pair(uint64_t key_size, uint64_t public_key);
		static void OAEP_padding(BinaryData& plain, uint64_t key_size, const BinaryData& label, const dog_torch::crypto::hash::algorithm::Algorithm& alg);
		static void OAEP_unpadding(BinaryData& crypt, uint64_t key_size, const BinaryData& label, const dog_torch::crypto::hash::algorithm::Algorithm& alg);
		static BinaryData encrypt(const BinaryData& plain, const BinaryData& key, uint64_t size, std::function<void(BinaryData&)> padding);
		static BinaryData decrypt(const BinaryData& crypt, const BinaryData& key, uint64_t size, std::function<void(BinaryData&)> unpadding);

		virtual std::unique_ptr<Algorithm> clone() const;

		const Config& get_allow_config() const;
		Config get_config() const override;
		KeyPair generate_key_pair(uint64_t key_size) const override;
		crypt_func get_encrypt_func() const override;
		crypt_func get_decrypt_func() const override;
	};
}