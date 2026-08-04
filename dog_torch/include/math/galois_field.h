#pragma once
#include "export.h"

#include <cstdint>
#include <array>
#include <bitset>

namespace dog_torch::math::galois_field
{
	constexpr uint8_t gf256_mult(uint8_t a, uint8_t b, uint16_t n)
	{
		uint16_t max = a >= b ? a : b;
		uint16_t min = a < b ? a : b;
		uint16_t res = 0;
		for (uint8_t i = 0; i < 8; i++)
		{
			if ((min >> i) & 0x01)
			{
				res ^= max << i;
			}
		}
		for (uint8_t i = 0; i < 8; i++)
		{
			if (res >> (15 - i) & 0x01)
			{
				res ^= n << (7 - i);
			}
		}
		return static_cast<uint8_t>(res & 0xFF);
	}

	constexpr std::array<uint8_t, 256> gf256_mult_table(uint16_t n)
	{
		uint8_t a = 2;
		std::array<uint8_t, 256> res;
		std::bitset<256> map;
		res[0] = 1;
		while(true)
		{
			map = std::bitset<256>{};
			uint16_t i = 1;
			for (; i < 255; i++)
			{
				res[i] = gf256_mult(res[i - 1], a, n);
				if (!map[res[i]]) map[res[i]] = true;
				else break;
			}
			if (i < 255 && a != 255)
			{
				++a;
				continue;
			}
			res[255] = 1;
			break;
		}
		if (a == 255) return std::array<uint8_t, 256>{};
		return res;
	}
	constexpr std::array<uint8_t, 256> gf256_mult_itable(uint16_t n)
	{
		std::array<uint8_t, 256> res;
		std::array<uint8_t, 256> mult_table = gf256_mult_table(n);
		for (uint8_t i = 0; i < 255; i++)
		{
			res[mult_table[i]] = i;
		}
		return res;
	}

	uint8_t gf256_mult_t(uint8_t a, uint8_t b, const std::array<uint8_t, 256>& table, const std::array<uint8_t, 256>& itable);
}