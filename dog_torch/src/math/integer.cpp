#include "math/integer.h"

namespace NSROOT = dog_torch::math::integer;

#ifdef WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "Bcrypt.lib")
#elif defined(__linux__) || defined(__APPLE__)
#include <sys/random.h>

#else
#include <random>
#endif

uint8_t NSROOT::available_size(uint64_t n)
{
    uint8_t len = 8;
    while (len > 1 && !(n >> ((len - 1) << 3)))
    {
        --len;
    }
    return len;
}

uint8_t NSROOT::pick_byte(uint64_t n, uint8_t i)
{
    return n >> (i << 3) & 0xFF;
}

NSROOT::BigUInt NSROOT::get_2_power(uint64_t n)
{
    using vec64 = std::vector<uint64_t>;
    vec64 r(n / 64 + 1);
    r.back() = (uint64_t)1 << (n % 64);
    return { r };
}
NSROOT::BigUInt NSROOT::random_num(const BigUInt& a, const BigUInt& b)
{
	using vec64 = std::vector<uint64_t>;
	std::random_device rd;
	auto random_uint64 = []()->uint64_t
		{
#ifdef WIN32
			uint64_t r = 0;
			BCryptGenRandom(NULL, reinterpret_cast<unsigned char*>(&r), sizeof(r), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
			return r;
#elif defined(__linux__) || defined(__APPLE__)
			uint64_t r = 0;
			if (getrandom(&r, sizeof(r), 0) == -1) {
				throw DOG_EXCEPTION(array_to_view(ERROR_RANDOM));
			}
			return r;
#else
			std::random_device rd;
			return static_cast<uint64_t>(rd()) << 32 | rd();
#endif
		};
	auto random_byte = [&rd,&random_uint64](uint64_t max, uint64_t min)->uint64_t
		{
			uint64_t dur = max - min;
			if (dur == 0) return min;
			uint64_t r = 0, q = 0;
			u128div(1, 0, dur, &q, &r);
			uint64_t max_ = 0xFFFFFFFFFFFFFFFF - r + 1;
			r = random_uint64();
			while (r > max_)
			{
				r = (uint64_t)rd() << 32 | rd();
			}
			return r % dur + min;
		};
	const vec64& great = a.num_.size() > b.num_.size() ? a.num_ : b.num_;
	const vec64& small_ = a.num_.size() <= b.num_.size() ? a.num_ : b.num_;
	vec64 r(great.size());
	for (uint64_t i = 0; i < small_.size(); ++i)
	{
		r[i] = random_byte(great[i], small_[i]);
	}
	for (uint64_t i = small_.size(); i < great.size(); ++i)
	{
		r[i] = random_byte(great[i], 0);
	}
	BigUInt::trims(r);
	return { r };
}

NSROOT::BigUInt NSROOT::get_power_2_minus_1(uint64_t n)
{
	using vec64 = std::vector<uint64_t>;
	if (n == 0) return 0;
	n -= 1;
	vec64 r(n / 64 + 1, 0xFFFFFFFFFFFFFFFF);
	r.back() = 0xFFFFFFFFFFFFFFFF >> (64 - 1 - n % 64);
	return { r };
}

#ifdef SHARED
extern template CPP_API uint8_t NSROOT::uirotl<uint8_t>(uint8_t n, uint8_t i);
extern template CPP_API uint16_t NSROOT::uirotl<uint16_t>(uint16_t n, uint8_t i);
extern template CPP_API uint32_t NSROOT::uirotl<uint32_t>(uint32_t n, uint8_t i);
extern template CPP_API uint64_t NSROOT::uirotl<uint64_t>(uint64_t n, uint8_t i);

extern template CPP_API uint8_t NSROOT::uirotr<uint8_t>(uint8_t n, uint8_t i);
extern template CPP_API uint16_t NSROOT::uirotr<uint16_t>(uint16_t n, uint8_t i);
extern template CPP_API uint32_t NSROOT::uirotr<uint32_t>(uint32_t n, uint8_t i);
extern template CPP_API uint64_t NSROOT::uirotr<uint64_t>(uint64_t n, uint8_t i);
#endif // SHARED

#undef NSROOT