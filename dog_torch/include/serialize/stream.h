#pragma once
#include "export.h"

#include <string>
#include <iostream>

#include "utils/binops.h"

namespace dog_torch::serialize::stream
{
	CPP_API uint64_t read_bytes(
		const std::vector<uint8_t>& input, uint64_t total, uint64_t& now,
		std::vector<uint8_t>& buffer, uint64_t size,
		uint64_t& read_size
	);

	CPP_API uint64_t read_bytes(
		std::istream& input, uint64_t total, uint64_t& now,
		std::vector<uint8_t>& buffer, uint64_t size,
		uint64_t& read_size
	);

	CPP_API uint64_t read_bits(
		const std::vector<uint8_t>& input, uint64_t total, uint64_t& now, uint8_t& now_bit
		, std::vector<uint8_t>& buffer,
		uint64_t size, uint64_t& read_size);

	CPP_API uint64_t read_bits(
		std::istream& input, uint64_t total, uint64_t& now, uint8_t& now_bit,
		std::vector<uint8_t>& buffer, uint64_t size,
		uint64_t& read_size
	);

	CPP_API void write_bits(
		std::vector<uint8_t>& output, uint8_t& buffer_byte, uint8_t& next_bit_set,
		uint64_t input_size, 
		const std::vector<uint8_t>& buffer, uint64_t buffer_size
	);

	CPP_API void write_bits(
		std::ostream& output, uint8_t& buffer_byte, uint8_t& next_bit_set, 
		uint64_t input_size, 
		const std::vector<uint8_t>& buffer, uint64_t buffer_size
	);


}