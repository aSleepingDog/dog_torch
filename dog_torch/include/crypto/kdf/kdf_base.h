#pragma once
#include "export.h"

#include <iostream>

#include "crypto/mac/hmac_base.h"
#include "serialize/serialize.h"

//key derivation functions
namespace dog_torch::crypto::kdf
{
	using dog_torch::serialize::BinaryData;
	using dog_torch::crypto::mac::HMacGenerator;
	using hash_algorithm = dog_torch::crypto::hash::algorithm::Algorithm;

	class HKDF
	{
	private:
		HMacGenerator hmac;
	public:
		HKDF(const hash_algorithm& alg, const BinaryData salt, bool do_extract = true, BinaryData ikm = { "",0 });
		BinaryData derive(const BinaryData& info, uint64_t out_size);
	};
}