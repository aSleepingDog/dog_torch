#pragma once
#include "export.h"

#include <vector>
#include <string>
#include <cstdint>
#include <iostream>
#include <algorithm>

#include "number.h"
#include "integer.h"

namespace dog_torch::math::number_theory
{
	using BigUInt = dog_torch::math::number::BigUnsignedInteger;
	using CompareResult = dog_torch::math::number::CompareResult;
	namespace IntegerNS = dog_torch::math::integer;
	using vec64 = std::vector<uint64_t>;

	BigUInt remainder_2_power(const BigUInt& a, uint64_t n);

	BigUInt power_remainder(const BigUInt& a, const BigUInt& n, const BigUInt& m);

	std::tuple<BigUInt, std::pair<char, BigUInt>, std::pair<char, BigUInt>> exgcd(const BigUInt& a, const BigUInt& b);

	BigUInt exgcd_inverse(const BigUInt& a, const BigUInt& m);

	const std::vector<bool>& get_small_prime_bitmap();

	/*
	* @param n 待测数
	* @param start_prime_index 起始素数索引
	*  3-0 5-1 ... p - (p-3)/2
	* @param extra_test 在RSA时额外测试n-1对extra_test的素性
	*/
	bool is_possible_prime(const BigUInt& n, uint64_t start_prime_index = 0, uint64_t extra_test = 0);

	BigUInt generate_prime(uint64_t byte_length, uint64_t extra_test = 0);

}