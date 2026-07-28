#pragma once

#include <iostream>
#include <functional>

#include "serialize/serialize.h"
#include "crypto/hash/hash_base.h"
#include "mac_base.h"

namespace dog_torch::crypto::mac
{
	class CPP_API HMacGenerator : public MacGenerator
	{
	private:
		using hash_algorithm_t = hash::algorithm::Algorithm;
		using hash_algorithm_uptr = std::unique_ptr<hash_algorithm_t>;
		hash_algorithm_uptr hash_algorithm_ = nullptr;
	public:
		HMacGenerator(const BinaryData& key, const hash_algorithm_uptr& hash_algorithm);
		HMacGenerator(const BinaryData& key, hash_algorithm_uptr&& hash_algorithm) noexcept;
		~HMacGenerator() override;
		BinaryData generate(const BinaryData& data) override;
		hash_algorithm_t& get_hash_algorithm();
		BinaryData generate(std::istream& input, uint64_t total) override;
		BinaryData generate(PauseableChannel& pc, std::istream& input, uint64_t total) override;
		std::string fmt_string() const override;
	};
}