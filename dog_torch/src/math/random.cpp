#include "math/random.h"

namespace NSROOT = dog_torch::math::random;

#ifdef WIN32
	#include <windows.h>
	#include <bcrypt.h>
	#pragma comment(lib, "Bcrypt.lib")
#elif defined(__linux__)
	#include <sys/random.h>
#elif defined(__APPLE__)
	#include <stdlib.h>
#endif

uint64_t NSROOT::random_uint64() noexcept
{
	uint64_t r = 0;
#ifdef WIN32
	if (BCryptGenRandom(NULL, reinterpret_cast<unsigned char*>(&r), sizeof(r), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
	{
		std::terminate();
	}
#elif defined(__linux__)
	ssize_t n = getrandom(&r, sizeof(r), 0);
	if (n != static_cast<ssize_t>(sizeof(r)))
	{
		std::terminate();
	}
#elif defined(__APPLE__)
	arc4random_buf(&r, sizeof(r));
#else
	static_assert(false, "no secure RNG suooprt");
#endif
	return r;
}
void NSROOT::random_block(char* s, uint64_t len) noexcept
{
	uint64_t r = 0;
	uint64_t i = 0;
	for (; i + 8 <= len; i += 8)
	{
		r = random_uint64();
		memcpy(s + i, reinterpret_cast<void*>(&r), 8);
	}
	if (i < len)
	{
		r = random_uint64();
		memcpy(s + i, reinterpret_cast<void*>(&r), len - i);
	}
}