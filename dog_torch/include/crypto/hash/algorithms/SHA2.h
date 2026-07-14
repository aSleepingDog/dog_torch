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
	class DOG_TORCH_API SHA2 : public Algorithm
	{
	private:
		bool is_padding_80_ = false;
		bool is_padding_num_ = false;
	public:
		static uint64_t max();
		static const Config& allowed_config();

		SHA2(uint64_t effective);
		~SHA2() override = default;

		SHA2(const SHA2& sha2);
		SHA2& operator=(const SHA2& sha2);
		SHA2(SHA2&& sha2) noexcept;
		SHA2& operator=(SHA2&& sha2) noexcept;

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
		//具体实现
		static const uint32_t k_256[64];
		static uint32_t tick4B(const BinaryData& data, uint64_t size, uint64_t index);
		static uint32_t f1_64(uint32_t e, uint32_t f, uint32_t g, uint32_t h, const BinaryData& block, uint64_t size, uint64_t n);
		static uint32_t f2_64(uint32_t a, uint32_t b, uint32_t c);
		static const std::array<uint8_t, 32> IV_256;
		static const std::array<uint8_t, 32> IV_224;
		static void single_256_update(const BinaryData& block_, BinaryData& value);
		static const uint64_t k_512[80];
		static uint64_t tick8B(const BinaryData& data, uint64_t size, uint64_t index);
		static uint64_t f1_128(uint64_t e, uint64_t f, uint64_t g, uint64_t h, const BinaryData& block, uint64_t size, uint64_t n);
		static uint64_t f2_128(uint64_t a, uint64_t b, uint64_t c);
		static const std::array<uint8_t, 64> IV_512;
		static const std::array<uint8_t, 64> IV_384;
		static void single_512_update(const BinaryData& block_, BinaryData& value);
	};
}


#define NAMESPACE(name) dog_torch__crypto__hash__SHA2_##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

extern "C"
{
	C_API(SERIALIZE(BinaryData)*)  NAMESPACE(256_binary)(const LVALUE(SERIALIZE(BinaryData)) data);
	C_API(SERIALIZE(BinaryData)*)  NAMESPACE(224_binary)(const LVALUE(SERIALIZE(BinaryData)) data);
	C_API(SERIALIZE(BinaryData)*)  NAMESPACE(384_binary)(const LVALUE(SERIALIZE(BinaryData)) data);
	C_API(SERIALIZE(BinaryData)*)  NAMESPACE(512_binary)(const LVALUE(SERIALIZE(BinaryData)) data);

	C_API(SERIALIZE(BinaryData)*)  NAMESPACE(256_file)(LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(UTILS(CppString)) path);
	C_API(SERIALIZE(BinaryData)*)  NAMESPACE(224_file)(LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(UTILS(CppString)) path);
	C_API(SERIALIZE(BinaryData)*)  NAMESPACE(384_file)(LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(UTILS(CppString)) path);
	C_API(SERIALIZE(BinaryData)*)  NAMESPACE(512_file)(LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(UTILS(CppString)) path);
}

#undef NAMESPACE
#undef SERIALIZE
#undef UTILS