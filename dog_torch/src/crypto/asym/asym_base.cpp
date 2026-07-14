#include "crypto/asym/asym_base.h"

namespace NSROOT = dog_torch::crypto::asym;
using BinaryData = dog_torch::serialize::BinaryData;

NSROOT::KeyPair::KeyPair(const BinaryData& public_key, const BinaryData& private_key)
	: public_key(public_key), private_key(private_key)
{}

NSROOT::algorithm::Config::Config(const std::string& name, const std::string& key_size_region)
	: name(name), key_size_region(key_size_region)
{}

NSROOT::algorithm::Algorithm::~Algorithm() = default;

std::unique_ptr<NSROOT::algorithm::Algorithm> NSROOT::algorithm::Algorithm::clone() const
{
	return std::make_unique<NSROOT::algorithm::Algorithm>(*this);
}

NSROOT::KeyPair NSROOT::algorithm::Algorithm::generate_key_pair(uint64_t key_size) const
{
	return { BinaryData(), BinaryData() };
}

NSROOT::algorithm::crypt_func NSROOT::algorithm::Algorithm::get_encrypt_func() const
{
	return crypt_func();
}
NSROOT::algorithm::crypt_func NSROOT::algorithm::Algorithm::get_decrypt_func() const
{
	return crypt_func();
}

