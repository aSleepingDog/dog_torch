#include "math/number_theory.h"

namespace NSROOT = dog_torch::math::number_theory;

NSROOT::BigUInt NSROOT::remainder_2_power(const BigUInt& a, uint64_t n)
{
	if (n == 0) return 0;
	uint64_t n_len = n / 64;
	uint64_t n_bit = n % 64;
	if (n_bit == 0)
	{
		return vec64(a.num_.begin(), a.num_.begin() + n_len);
	}
	if (a.num_.size() <= n_len)
	{
		return a;
	}
	n_len += 1;
	vec64 r(a.num_.begin(), a.num_.begin() + n_len);
	r.back() &= 0xFFFFFFFFFFFFFFFF >> (64 - n_bit);
	return r;
};
NSROOT::BigUInt NSROOT::power_remainder(const BigUInt& a, const BigUInt& n, const BigUInt& m)
{
	BigUInt result = vec64{ 1 };
	BigUInt a_ = a % m;
	for (uint64_t n_ : n.num_)
	{
		for (uint64_t i = 0; i < 64; ++i)
		{
			if (n_ & 1) result = (result * a_) % m;
			a_ = (a_ * a_) % m;
			n_ >>= 1;
		}
	}
	return result;
};
std::tuple<NSROOT::BigUInt, std::pair<char, NSROOT::BigUInt>, std::pair<char, NSROOT::BigUInt>> NSROOT::exgcd(const BigUInt& a, const BigUInt& b)
{
	auto mul = [](const std::pair<char, BigUInt>& a, const BigUInt& b)->std::pair<char, BigUInt>
		{
			return { b == vec64{0} ? 0 : a.first, a.second * b };
		};
	auto sub = [](const std::pair<char, BigUInt>& a, const std::pair<char, BigUInt>& b) -> std::pair<char, BigUInt>
		{
			char a_s = a.first, b_s = b.first;
			b_s *= -1;
			if (a_s == b_s)
			{
				return { a_s, (a.second + b.second) };
			}
			else
			{
				auto abs_compare_res = BigUInt::v_compare(a.second.num_, b.second.num_);
				if (abs_compare_res == CompareResult::EQUAL && a_s != b_s)
				{
					return { 0,0 };
				}
				char target_sign = abs_compare_res == CompareResult::GREATER ? a_s : b_s;
				return { target_sign,
					abs_compare_res == CompareResult::GREATER ?
					(a.second - b.second) :
					(b.second - a.second),
				};
			}
		};
	BigUInt r = b, o_r = a;
	std::pair<char, BigUInt> s = { 1, 1 }, o_s = { 0, 0 }, t_s;
	std::pair<char, BigUInt> t = { 0, 0 }, o_t = { 1, 1 }, t_t;
	while (BigUInt::v_compare(r.num_, { 0 }) != CompareResult::EQUAL)
	{
		auto q_r = BigUInt::v_divide(o_r.num_, r.num_);
		o_r = r;
		r = q_r.second;

		t_s = s;
		s = sub(o_s, mul(s, q_r.first));
		o_s = t_s;

		t_t = t;
		t = sub(o_t, mul(t, q_r.first));
		o_t = t_t;
	}
	return { o_r, o_t, o_s };
}
NSROOT::BigUInt NSROOT::exgcd_inverse(const BigUInt& a, const BigUInt& m)
{
	auto [gcd, x, y] = exgcd(a, m);
	if (BigUInt::v_compare(gcd.num_, { 1 }) != CompareResult::EQUAL)
	{
		return 0;
	}
	if (x.first == 1)
	{
		return BigUInt(x.second);
	}
	return BigUInt(BigUInt::v_subtract(m.num_, x.second.num_));
}
const std::vector<bool>& NSROOT::get_small_prime_bitmap()
{
	constexpr uint64_t MAX_PRIME = 1000005;
	constexpr uint64_t MAX_PRIME_SQUARE_ROOT = 1000;
	static std::vector<bool> bitmap;
	if (bitmap.empty())
	{
		bitmap.resize((MAX_PRIME - 3) / 2, true);
		for (uint64_t i = 0; i < bitmap.size(); ++i)
		{
			uint64_t real = i * 2 + 3;
			if (real > MAX_PRIME_SQUARE_ROOT) break;
			if (bitmap[i])
			{
				for (uint64_t no_prime_real = real * 3; no_prime_real < MAX_PRIME; no_prime_real += 2 * real)
				{
					bitmap[(no_prime_real - 3) / 2] = false;
				}
			}
		}
	}
	return bitmap;
};
bool NSROOT::is_possible_prime(const BigUInt& n, uint64_t start_prime_index, uint64_t extra_test)
{
	if (n < 2) return false;
	if (n.num_.front() % 2 == 0) return false;
	const auto& bitmap = get_small_prime_bitmap();
	for (uint64_t i = start_prime_index; i < bitmap.size(); ++i)
	{
		if (!bitmap[i]) continue;
		uint64_t real = i * 2 + 3;
		if ((n % real) == BigUInt(vec64{ 0 })) return false;
	}
	if (extra_test != 0)
	{
		if (((n - 1) % extra_test) == BigUInt(vec64{ 0 })) return false;
	}
	std::vector<BigUInt> a;
	if (n < IntegerNS::get_2_power(64))
	{
		a = { 2, 325, 9375, 28178, 450775, 9780504, 1795265022 };
	}
	else
	{
		for (uint64_t i = 0; i < 64; ++i)
		{
			a.push_back({ IntegerNS::random_num({2},(n - 2).num_) });
		}
	}
	uint64_t s = 0;
	BigUInt d = n - 1;
	while (d.num_.front() % 2 == 0)
	{
		s++;
		d >>= 1;
	}

	for (uint64_t i = 0; i < a.size(); ++i)
	{
		//std::cout << i << std::endl;
		//BigUInt x = power_remainder_montgomery(a[i], d, n);
		BigUInt x = power_remainder(a[i], d, n);
		if (x != 1 && x != n - 1)
		{
			for (uint64_t r = 0; r < s - 1 && x != n - 1; ++r)
			{
				x = x * x % n;
				if (x == 1)
				{
					return false;
				}
			}
			if (x != n - 1)
			{
				return false;
			}
		}
	}
	return true;
};
NSROOT::BigUInt NSROOT::generate_prime(uint64_t byte_length, uint64_t extra_test)
{
	BigUInt big_pi = 6;
	BigUInt max = BigUInt{ IntegerNS::get_power_2_minus_1(byte_length * 8) };
	BigUInt max_r = max / big_pi;
	BigUInt min = BigUInt{ IntegerNS::get_power_2_minus_1(byte_length * 8 - 1) };
	BigUInt min_r = min / big_pi;
	BigUInt q = BigUInt{ IntegerNS::random_num(min_r.num_, max_r.num_) } * big_pi + BigUInt{ std::vector<uint64_t>{1} };
	uint64_t i = 0;
	uint64_t test_times = 0;
	while (!is_possible_prime(q, 1, extra_test))
	{
		q += big_pi;
		if (q > max || test_times > 100)
		{
			q = BigUInt{ IntegerNS::random_num(min_r.num_, max_r.num_) } * big_pi + BigUInt{ std::vector<uint64_t>{1} };
			test_times = 0;
		}
	}
	return q;
}