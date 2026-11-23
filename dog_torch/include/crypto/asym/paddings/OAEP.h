#pragma once
#include "export.h"

#include "utils/compile.h"
#include "math/math.h"
#include "serialize/serialize.h"
#include "crypto/hash/hash_algorithms.h"
#include "crypto/asym/asym_base.h"

namespace dog_torch::crypto::asym::padding
{
	class OAEP : public Padding
	{
		using HashAlg = dog_torch::crypto::hash::algorithm::Algorithm;
		std::unique_ptr<HashAlg> t_alg_p_;
		std::unique_ptr<HashAlg> m_alg_p_;
		uint64_t key_size_;
		BinaryData label_;
	public:
		static BinaryData MGF1(const BinaryData& data, uint64_t output, const HashAlg& alg);
		static BinaryData padding(const BinaryData& plain, uint64_t key_size, const BinaryData& label, const HashAlg& alg);
		static BinaryData padding(const BinaryData& plain, uint64_t key_size, const BinaryData& label, const HashAlg& t_alg, const HashAlg& m_alg);
		static BinaryData unpadding(const BinaryData& crypt, uint64_t key_size, const BinaryData& label, const HashAlg& alg);
		static BinaryData unpadding(const BinaryData& crypt, uint64_t key_size, const BinaryData& label, const HashAlg& t_alg, const HashAlg& m_alg);

		OAEP(const HashAlg& alg, uint64_t key_size, const BinaryData& label);
		OAEP(const HashAlg& t_alg, const HashAlg& m_alg, uint64_t key_size, const BinaryData& label);

		OAEP(const OAEP& other);
		OAEP& operator=(const OAEP& other);
		OAEP(OAEP&& other) noexcept;
		OAEP& operator=(OAEP&& other) noexcept;

		const Config& get_allow_config() const;
		bool check(const algorithm::Algorithm& alg) override;
		Config get_config() const override;
		std::unique_ptr<Padding> clone() const override;

		padding_func get_padding() const override;
		padding_func get_unpadding() const override;
	};
}