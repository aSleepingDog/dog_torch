#pragma once
#include "export.h"

#include <iostream>
#include <functional>

#include "serialize/serialize.h"

namespace dog_torch::crypto::asym
{
	using BinaryData = dog_torch::serialize::BinaryData;

	struct KeyPair
	{
		BinaryData public_key;
		BinaryData private_key;
		KeyPair(const BinaryData& public_key, const BinaryData& private_key);
	};

	namespace algorithm
	{
		struct Config
		{
			std::string name;
			std::string key_size_region;
			Config(const std::string& name, const std::string& key_size_region);
		};

		using crypt_func = std::function<void(BinaryData&, const BinaryData&, uint64_t)>;

		struct Algorithm
		{
			virtual KeyPair generate_key_pair(uint64_t key_size) const;
			virtual crypt_func get_encrypt_func() const;
			virtual crypt_func get_decrypt_func() const;

			virtual ~Algorithm();

			virtual std::unique_ptr<Algorithm> clone() const;

		};
	}
}
