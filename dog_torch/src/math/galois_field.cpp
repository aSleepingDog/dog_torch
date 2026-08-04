#include "math/galois_field.h"

uint8_t dog_torch::math::galois_field::gf256_mult_t(uint8_t a, uint8_t b, const std::array<uint8_t, 256>& table, const std::array<uint8_t, 256>& itable)
{
	if (a == 0 || b == 0) return 0;
	return table[(itable[a] + itable[b]) % 255];
}