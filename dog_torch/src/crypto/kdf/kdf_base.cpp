#include "crypto/kdf/kdf_base.h"

namespace NSROOT = dog_torch::crypto::kdf;
using dog_torch::serialize::BinaryData;

NSROOT::HKDF::HKDF(const hash_algorithm& alg, const BinaryData salt, bool do_extract, BinaryData ikm)
	: hmac(salt, alg.clone())
{
	if (do_extract)
	{
		auto prk = hmac.generate(ikm);
		this->hmac.set_key(prk);
	}
	else
	{
		this->hmac.set_key(salt);
	}
}

BinaryData NSROOT::HKDF::derive(const BinaryData& info, uint64_t out_size)

{
	if (this->hmac.get_hash_algorithm().get_out_size() * 255 < out_size)
	{
		throw std::runtime_error("Out size is too big");
	}
	uint8_t i = 1;
	BinaryData out = info;
	out.push_back(i++);
	out = this->hmac.generate(out);
	BinaryData tmp = out;
	uint64_t times = out_size / this->hmac.get_hash_algorithm().get_out_size();
	for (; i < times; ++i)
	{
		BinaryData info_ = info;
		info_.push_back(i);
		out += this->hmac.generate(tmp + info_);
	}
	uint64_t remainder = out_size % this->hmac.get_hash_algorithm().get_out_size();
	if (remainder != 0)
	{
		BinaryData info_ = info;
		info_.push_back(i);
		out += this->hmac.generate(tmp + info_).sub_bytes_len(0, remainder);
	}
	return out;
}
