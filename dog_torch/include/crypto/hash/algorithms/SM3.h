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
	class CPP_API SM3 : public Algorithm
	{
	private:
		bool is_padding_80_ = false;
		bool is_padding_num_ = false;
	public:
		static uint64_t max();
		static const Config& allowed_config();

		SM3();
		~SM3() override = default;

		SM3(const SM3& other);
		SM3& operator=(const SM3& other);
		SM3(SM3&& other) noexcept;
		SM3& operator=(SM3&& other) noexcept;

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
		static const std::array<uint8_t, 32> IV;
		static uint32_t tick4B(const BinaryData& data, uint64_t index);
		static uint32_t P1(const BinaryData& data, uint64_t index);
		static uint32_t FF1(uint32_t a, uint32_t b, uint32_t c, int i);
		static uint32_t GG1(uint32_t a, uint32_t b, uint32_t c, int i);
		static void single_update(const BinaryData& block_, BinaryData& value);
	};
}

#define NAMESPACE(name) dog_torch__crypto__hash__SM3_##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

extern "C"
{
	C_API(SERIALIZE(BinaryData)*)  NAMESPACE(binary) (const LVALUE(SERIALIZE(BinaryData)) data);
	C_API(SERIALIZE(BinaryData)*)  NAMESPACE(file)   (LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(UTILS(CppString)) path);
}

#undef NAMESPACE
#undef SERIALIZE
#undef UTILS