#pragma once
#include "export.h"

#include <vector>
#include <string>
#include <iostream>

#include "math/number.h"
#include "BinaryData.h"

namespace dog_torch::serialize::stream
{
	CPP_API uint64_t read_bytes(
		const BinaryData& input, uint64_t total, uint64_t& now,
		BinaryData& buffer, uint64_t size,
		uint64_t& read_size
	);
	CPP_API uint64_t read_bytes(
		std::istream& input, uint64_t total, uint64_t& now,
		BinaryData& buffer, uint64_t size,
		uint64_t& read_size
	);

	CPP_API uint64_t read_bits(
		const BinaryData& input, uint64_t total, uint64_t& now, uint8_t& now_bit
		, BinaryData& buffer,
		uint64_t size, uint64_t& read_size);

	CPP_API uint64_t read_bits(
		std::istream& input, uint64_t total, uint64_t& now, uint8_t& now_bit,
		BinaryData& buffer, uint64_t size,
		uint64_t& read_size
	);

	CPP_API void write_bits(
		BinaryData& output, uint8_t& buffer_byte, uint8_t& next_bit_set, 
		uint64_t input_size, 
		const BinaryData& buffer, uint64_t buffer_size
	);

	CPP_API void write_bits(
		std::ostream& output, uint8_t& buffer_byte, uint8_t& next_bit_set, 
		uint64_t input_size, 
		const BinaryData& buffer, uint64_t buffer_size
	);


}