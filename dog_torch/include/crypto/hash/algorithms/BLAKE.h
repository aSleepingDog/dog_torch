#pragma once
#include "export.h"

#include <iostream>
#include <functional>

#include "utils/compile.h"
#include "math/math.h"
#include "serialize/serialize.h"
#include "../hash_base.h"

namespace dog_torch::crypto::hash::algorithm
{
	using dog_torch::math::number::UnsignedInteger128;
	class CPP_API BLAKE2 : public Algorithm
	{
	private:
		uint64_t t_low = 0;
		uint64_t f0 = 0;
		uint8_t out_size = 0;
		BinaryData key;
		BinaryData p;
	public:
		static const Config& allowed_config();

		BLAKE2(uint64_t effective, uint8_t out_size = 0, 
			const BinaryData& key = { "",BinaryData::Type::Hex }, 
			const BinaryData& salt = { "",BinaryData::Type::Hex }, 
			const BinaryData& personalization = { "",BinaryData::Type::Hex }
		);

		~BLAKE2() override = default;

		BLAKE2(const BLAKE2& other);
		BLAKE2& operator=(const BLAKE2& other);
		BLAKE2(BLAKE2&& other) noexcept;
		BLAKE2& operator=(BLAKE2&& other) noexcept;

		Config config() const override;
		std::string fmt_string() const override;

		void init() override;
		BinaryData init_data() const override;
		update_func get_update() const override;
		trims_func get_trims() const override;
		uint64_t get_block_size() const override;
		uint64_t get_out_size() const override;
		std::unique_ptr<Algorithm> clone() const override;

		bool have_next_block(uint64_t data_pos, uint64_t data_total) override;
		BinaryData next_block(const BinaryData& data, uint64_t start, uint64_t& data_pos, uint64_t data_total) override;
		BinaryData next_block(std::istream& data, uint64_t& data_pos, uint64_t data_total) override;

		static uint8_t Sigma[12][16];
		static const std::array<uint8_t, 32> IV_32;
		static const std::array<uint8_t, 64> IV_64;

		static void g_64(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d, uint64_t m0, uint64_t m1);
		static void update_64(const BinaryData& block, BinaryData& value, uint64_t t_low, uint64_t f0);
		static void g_32(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t m0, uint32_t m1);
		static void update_32(const BinaryData& block, BinaryData& value, uint32_t t_low, uint32_t f0);
	};
}

#define NS_BLAKE2(name) dog_torch__crypto__hash__BLAKE2_##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

extern "C"
{
	C_API(SERIALIZE(BinaryData)*)  NS_BLAKE2(64_binary)(const LVALUE(SERIALIZE(BinaryData)) data, uint64_t effective, uint8_t out_size, const LVALUE(SERIALIZE(BinaryData)) key, const LVALUE(SERIALIZE(BinaryData)) salt, const LVALUE(SERIALIZE(BinaryData)) personalization);
	C_API(SERIALIZE(BinaryData)*)  NS_BLAKE2(32_binary)(const LVALUE(SERIALIZE(BinaryData)) data, uint64_t effective, uint8_t out_size, const LVALUE(SERIALIZE(BinaryData)) key, const LVALUE(SERIALIZE(BinaryData)) salt, const LVALUE(SERIALIZE(BinaryData)) personalization);

	C_API(SERIALIZE(BinaryData)*)  NS_BLAKE2(64_file)(LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(UTILS(CppString)) path, uint64_t effective, uint8_t out_size, const LVALUE(SERIALIZE(BinaryData)) key, const LVALUE(SERIALIZE(BinaryData)) salt, const LVALUE(SERIALIZE(BinaryData)) personalization);
	C_API(SERIALIZE(BinaryData)*)  NS_BLAKE2(32_file)(LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(UTILS(CppString)) path, uint64_t effective, uint8_t out_size, const LVALUE(SERIALIZE(BinaryData)) key, const LVALUE(SERIALIZE(BinaryData)) salt, const LVALUE(SERIALIZE(BinaryData)) personalization);
}

#undef NAMESPACE
#undef SERIALIZE
#undef UTILS