#pragma once
#include "export.h"

#include <string>
#include <vector>
#include <cstdint>

namespace dog_torch::utils
{
	CPP_API std::string to_utf8(uint64_t code);
	CPP_API std::string to_string(std::u8string_view u8str);

	CPP_API std::vector<uint8_t> sub_bytes_pos(const std::vector<uint8_t>& input, uint64_t start, uint64_t end);
	CPP_API std::vector<uint8_t> sub_bytes_len(const std::vector<uint8_t>& input, uint64_t start, uint64_t length);
	CPP_API std::vector<uint8_t> bit_move(const std::vector<uint8_t>& input, bool is_right, bool allow_resize, uint64_t shift);
	CPP_API void bit_move_self(std::vector<uint8_t>& input, bool is_right, bool allow_resize, uint64_t shift);
	CPP_API std::vector<uint8_t> sub_bits_pos(const std::vector<uint8_t>& input, uint64_t start, uint8_t start_bit, uint64_t end, uint8_t end_bit);
	CPP_API std::vector<uint8_t> sub_bits_len(const std::vector<uint8_t>& input, uint64_t start, uint8_t start_bit, uint64_t lenght);
}