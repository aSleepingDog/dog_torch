#pragma once
#include "export.h"

#include <bit>
#include <vector>
#include <string>
#include <cstdint>
#include <random>

#include "utils/exception.h"
#include "number.h"

namespace dog_torch::math::integer
{
	using BigUInt = dog_torch::math::number::BigUnsignedInteger;

	BigUInt get_2_power(uint64_t n);

	BigUInt random_num(const BigUInt& a, const BigUInt& b);

	BigUInt get_power_2_minus_1(uint64_t n);

	DOG_TORCH_API uint8_t available_size(uint64_t n);
	DOG_TORCH_API uint8_t pick_byte(uint64_t n, uint8_t i);

	/*
	* 循环左移
	*/
	template<std::unsigned_integral NUMBER>
	NUMBER uirotl(NUMBER n, uint8_t i)
	{
		return std::rotl(n, i);
	}

	/*
	* 循环右移
	*/
	template<std::unsigned_integral NUMBER>
	NUMBER uirotr(NUMBER n, uint8_t i)
	{
		return std::rotr(n, i);
	}

}