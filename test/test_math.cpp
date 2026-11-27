#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <random>
#include <complex>
#include <map>
#include <deque>
#include <stack>
#include <algorithm>
#include <unordered_map>
#include <mutex>
#include <execution>
#include <shared_mutex>
#include <functional>
#include <thread>
#include <atomic>
#include <future>
#include <gmpxx.h>

#include "math/math.h"
using dog_torch::math::number::BigUnsignedInteger;

std::string random_num(uint64_t radix, uint64_t size)
{
	const char* charList = "0123456789ABCDEF";
	std::string str;
	str.reserve(size);
	std::random_device rd;
	auto rd_c = [&rd, radix, &charList]()->char
		{
			uint64_t max = 256 - (256 % radix);
			char r = rd() & 0xFF;
			while (r >= max)
			{
				r = rd() & 0xFF;
			}
			return charList[r % radix];
		};
	auto rd_h = [&rd, radix, &charList]()->char
		{
			uint64_t max = 256 - (256 % (radix - 1));
			char r = rd() & 0xFF;
			while (r >= max)
			{
				r = rd() & 0xFF;
			}
			return charList[r % (radix - 1) + 1];
		};
	str += rd_h();
	for (uint64_t i = 0; i < size - 1; ++i)
	{
		str += rd_c();
	}
	return str;
}
std::string g_convertRadix(const std::string& str, int ori_radix, int target_radix)
{
	// 使用GMP的大整数类型
	mpz_class num;

	// 从原始进制字符串解析
	int set_result = num.set_str(str, ori_radix);
	if (set_result != 0) {
		throw std::invalid_argument("Invalid number string for the given radix");
	}
	// 转换为目标进制字符串
	return num.get_str(target_radix);
}
std::string m_convertRadix(const std::string& str, int ori_radix, int target_radix)
{
	BigUnsignedInteger num(str, ori_radix);
	return num.to_num_str(target_radix, false);
}

void test_radix(uint64_t times, uint64_t max_size)
{
	std::map<std::string, std::tuple<uint64_t, double, double>> radixs_time;
	uint8_t radix[4] = { 2, 8,10,16 };
	char radix_c[5] = "28AF";

	std::random_device rd;

	auto start = std::chrono::steady_clock::now();
	auto end = std::chrono::steady_clock::now();

	double g_time = 0;
	double m_time = 0;

	uint64_t error = 0;

	for (uint64_t i = 0; i < times; ++i)
	{
		uint64_t size = (rd() % (max_size - 1)) + 1;
		uint8_t ori_radix_index = rd() % 4;
		uint8_t target_radix_index = rd() % 4;
		uint64_t ori_radix = radix[ori_radix_index];
		uint64_t target_radix = radix[target_radix_index];

		std::string key = (std::string() + radix_c[ori_radix_index] + "->" + radix_c[target_radix_index]);
		if (radixs_time.find(key) == radixs_time.end())
		{
			radixs_time[key] = { 0,0,0 };
		}

		std::string num_str = random_num(ori_radix, size);

		std::get<0>(radixs_time[key])++;
		start = std::chrono::steady_clock::now();
		std::string g_res = g_convertRadix(num_str, ori_radix, target_radix);
		end = std::chrono::steady_clock::now();
		g_time += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
		std::get<1>(radixs_time[key]) += g_time;

		start = std::chrono::steady_clock::now();
		std::string m_res = m_convertRadix(num_str, ori_radix, target_radix);
		end = std::chrono::steady_clock::now();
		m_time += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
		std::get<2>(radixs_time[key]) += m_time;

		if (g_res != m_res)
		{
			error++;
			std::cout << num_str << std::endl;
			std::cout << ori_radix << "->" << target_radix << std::endl;
			std::cout << g_res << std::endl;
			std::cout << m_res << std::endl;
			std::cout << std::endl;
		}
	}
	std::cout << "error:" << error << std::endl;
	std::cout << "g:" << g_time / times << std::endl;
	std::cout << "m:" << m_time / times << std::endl;
	std::cout << "m/g:" << m_time / g_time << std::endl;
	for (auto [key, value] : radixs_time)
	{
		std::cout << key << std::endl;
		std::cout << "time:" << std::get<0>(value) << std::endl;
		std::cout << "g:" << std::get<1>(value) / std::get<0>(value) << std::endl;
		std::cout << "m:" << std::get<2>(value) / std::get<0>(value) << std::endl;
		std::cout << "m/g:" << std::get<2>(value) / std::get<1>(value) << std::endl;
	}
}
void test_add(uint64_t times, uint64_t max_size)
{
	double g_time = 0;
	double m_time = 0;
	uint64_t error = 0, size = 0;;
	auto start = std::chrono::steady_clock::now();
	auto end = std::chrono::steady_clock::now();
	std::string a_s, b_s, c_gs, c_ms;
	BigUnsignedInteger a_m, b_m, c_m;
	mpz_class a_g, b_g, c_g;
	std::random_device rd;
	for (uint64_t i = 0; i < times; ++i)
	{
		size = (rd() % (max_size - 1)) + 1;
		a_s = random_num(10, size);
		size = (rd() % (max_size - 1)) + 1;
		b_s = random_num(10, size);

		a_m = BigUnsignedInteger{ a_s,10 };
		b_m = BigUnsignedInteger{ b_s,10 };

		a_g = a_s;
		b_g = b_s;

		start = std::chrono::steady_clock::now();
		c_g = a_g + b_g;
		end = std::chrono::steady_clock::now();
		g_time += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
		c_gs = c_g.get_str(16);

		start = std::chrono::steady_clock::now();
		c_m = a_m + b_m;
		end = std::chrono::steady_clock::now();
		m_time += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
		c_ms = c_m.to_num_str(16, false);

		if (c_gs != c_ms)
		{
			error++;
			std::cout << a_s << std::endl;
			std::cout << "+" << std::endl;
			std::cout << b_s << std::endl;
			std::cout << c_gs << std::endl;
			std::cout << c_ms << std::endl;
			std::cout << std::endl;
		}
	}
	std::cout << "error:" << error << std::endl;
	std::cout << "g:" << g_time / times << std::endl;
	std::cout << "m:" << m_time / times << std::endl;
	std::cout << "m/g:" << m_time / g_time << std::endl;
}
void test_subtract(uint64_t times, uint64_t max_size)
{
	double g_time = 0;
	double m_time = 0;
	uint64_t error = 0, size = 0;
	auto start = std::chrono::steady_clock::now();
	auto end = std::chrono::steady_clock::now();
	std::string a_s, b_s, c_gs, c_ms;
	BigUnsignedInteger a_m, b_m, c_m;
	mpz_class a_g, b_g, c_g;
	std::random_device rd;
	for (uint64_t i = 0; i < times; ++i)
	{
		size = (rd() % (max_size - 1)) + 1;
		a_s = random_num(10, size);
		size = (rd() % (max_size - 1)) + 1;
		b_s = random_num(10, size);

		a_g = a_s;
		b_g = b_s;

		a_m = BigUnsignedInteger{ a_s,10 };
		b_m = BigUnsignedInteger{ b_s,10 };

		if (a_g < b_g)
		{
			std::swap(a_s, b_s);
			std::swap(a_g, b_g);
			std::swap(a_m, b_m);
		}

		start = std::chrono::steady_clock::now();
		c_g = a_g - b_g;
		end = std::chrono::steady_clock::now();
		g_time += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
		c_gs = c_g.get_str(16);

		start = std::chrono::steady_clock::now();
		c_m = a_m - b_m;
		end = std::chrono::steady_clock::now();
		m_time += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
		c_ms = c_m.to_num_str(16, false);

		if (c_gs != c_ms)
		{
			error++;
			std::cout << a_s << std::endl;
			std::cout << "-" << std::endl;
			std::cout << b_s << std::endl;
			std::cout << c_gs << std::endl;
			std::cout << c_ms << std::endl;
			std::cout << std::endl;
		}
	}
	std::cout << "error:" << error << std::endl;
	std::cout << "g:" << g_time / times << std::endl;
	std::cout << "m:" << m_time / times << std::endl;
	std::cout << "m/g:" << m_time / g_time << std::endl;
}
void test_multiply(uint64_t times, uint64_t max_size)
{
	double g_time = 0;
	double m_time = 0;
	uint64_t error = 0, size = 0;
	auto start = std::chrono::steady_clock::now();
	auto end = std::chrono::steady_clock::now();
	std::string a_s, b_s, c_gs, c_ms;
	BigUnsignedInteger a_m, b_m, c_m;
	mpz_class a_g, b_g, c_g;
	std::random_device rd;
	for (uint64_t i = 0; i < times; ++i)
	{
		size = (rd() % (max_size - 1)) + 1;
		a_s = random_num(10, size);
		size = (rd() % (max_size - 1)) + 1;
		b_s = random_num(10, size);

		//std::cout << a_s << std::endl << b_s << std::endl << std::endl;

		a_m = BigUnsignedInteger{ a_s,10 };
		b_m = BigUnsignedInteger{ b_s,10 };

		a_g = a_s;
		b_g = b_s;

		start = std::chrono::steady_clock::now();
		c_g = a_g * b_g;
		end = std::chrono::steady_clock::now();
		g_time += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
		c_gs = c_g.get_str(16);

		start = std::chrono::steady_clock::now();
		c_m = a_m * b_m;
		end = std::chrono::steady_clock::now();
		m_time += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
		c_ms = c_m.to_num_str(16, false);

		if (c_gs != c_ms)
		{
			error++;
			std::cout << a_s << std::endl;
			std::cout << "*" << std::endl;
			std::cout << b_s << std::endl;
			std::cout << c_gs << std::endl;
			std::cout << c_ms << std::endl;
			for (uint64_t i = 0; i < std::min(c_gs.size(), c_ms.size()); ++i)
			{
				if (c_gs[i] != c_ms[i]) std::cout << '^';
				else std::cout << '-';
			}
			std::cout << std::endl;
		}
	}
	std::cout << "error:" << error << std::endl;
	std::cout << "g:" << g_time / times << std::endl;
	std::cout << "m:" << m_time / times << std::endl;
	std::cout << "m/g:" << m_time / g_time << std::endl;
}
void test_divide(uint64_t times, uint64_t max_size)
{
	double g_time = 0;
	double m_time = 0;
	uint64_t error = 0, size = 0;
	auto start = std::chrono::steady_clock::now();
	auto end = std::chrono::steady_clock::now();
	std::string a_s, b_s, c_gs, c_ms;
	BigUnsignedInteger a_m, b_m, c_m;
	mpz_class a_g, b_g, c_g;
	std::random_device rd;
	for (uint64_t i = 0; i < times; ++i)
	{
		size = (rd() % (max_size - 1)) + 1;
		a_s = random_num(10, size);
		size = (rd() % (max_size - 1)) + 1;
		b_s = random_num(10, size);

		a_g = a_s;
		b_g = b_s;

		a_m = BigUnsignedInteger{ a_s,10 };
		b_m = BigUnsignedInteger{ b_s,10 };

		if (a_g < b_g)
		{
			std::swap(a_s, b_s);
			std::swap(a_g, b_g);
			std::swap(a_m, b_m);
		}

		start = std::chrono::steady_clock::now();
		c_g = a_g / b_g;
		end = std::chrono::steady_clock::now();
		g_time += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
		c_gs = c_g.get_str(16);

		start = std::chrono::steady_clock::now();
		c_m = a_m / b_m;
		end = std::chrono::steady_clock::now();
		m_time += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
		c_ms = c_m.to_num_str(16, false);

		if (c_gs != c_ms)
		{
			error++;
			std::cout << a_s << std::endl;
			std::cout << "/" << std::endl;
			std::cout << b_s << std::endl;
			std::cout << c_gs << std::endl;
			std::cout << c_ms << std::endl;
			std::cout << std::endl;
		}
	}
	std::cout << "error:" << error << std::endl;
	std::cout << "g:" << g_time / times << std::endl;
	std::cout << "m:" << m_time / times << std::endl;
	std::cout << "m/g:" << m_time / g_time << std::endl;
}
void test_prime(uint64_t byte_length)
{
	namespace INS = dog_torch::math::integer;
	namespace NTNS = dog_torch::math::number_theory;
	/*
	* 64   =  512    r-0.5s
	* 128  =  1024   r-1.5s
	* 256  =  2048   r-5s
	* 384  =  3072   r-15s 21s
	* 512  =  4096   r-40s
	*/
	//6 6469693230
	BigUnsignedInteger big_pi = 6;
	BigUnsignedInteger max = BigUnsignedInteger{ INS::get_power_2_minus_1(byte_length * 8) };
	BigUnsignedInteger max_r = max / big_pi;
	BigUnsignedInteger min = BigUnsignedInteger{ INS::get_power_2_minus_1(byte_length * 8 - 1) };
	BigUnsignedInteger min_r = min / big_pi;
	std::random_device rd;
	BigUnsignedInteger q = BigUnsignedInteger{ INS::random_num(min_r.num_, max_r.num_) } * big_pi + BigUnsignedInteger{ std::vector<uint64_t>{1} };
	uint64_t i = 0;
	uint64_t test_times = 0;
	while (!NTNS::is_possible_prime(q, 1))
	{
		std::cout << "test:" << i++ << std::endl;
		mpz_class q_(q.to_num_str(10).c_str());
		int temp_result = mpz_probab_prime_p(q_.get_mpz_t(), 64);
		std::cout << (temp_result != 0 ? " prime-------------------------------" : " composite") << std::endl;
		++test_times;
		q += big_pi;
		if (q > max || test_times > 100)
		{
			q = BigUnsignedInteger{ INS::random_num(min_r.num_, max_r.num_) } * big_pi + BigUnsignedInteger{ std::vector<uint64_t>{1} };
			test_times = 0;
		}
	}
	std::cout << q.to_num_str(10) << std::endl;

	mpz_class q_(q.to_num_str(10).c_str());

	int result = mpz_probab_prime_p(q_.get_mpz_t(), 64);
	if (result == 2)
	{
		std::cout << "prime" << std::endl;
	}
	else if (result == 1)
	{
		std::cout << "probably prime" << std::endl;
	}
	else
	{
		std::cout << "composite" << std::endl;
	}
}
int main()
{
	//test_radix(2048, 4096);
	test_add(2048, 1024);
	test_subtract(2048, 1024);
	test_multiply(2048, 1024);
	test_divide(2048, 1024);

	//auto start = std::chrono::steady_clock::now();
	//constexpr uint64_t max = 16;
	//for (uint64_t i = 0; i < max; ++i)
	//	test_prime(512);
	//auto end = std::chrono::steady_clock::now();
	//std::cout << std::chrono::duration_cast<
	//	std::chrono::milliseconds
	//>(end - start).count() * 1.0 / max << std::endl;

	//test_prime(256);
	//test_prime(256);

	//using BigUInt = BigUnsignedInteger;

	//BigUInt p = "3161";

	//BigUInt q = "205411";

	//BigUInt n = p * q;
	//BigUInt t = n - p - q + 1;
	//BigUInt e = 65537;

	//BigUInt d = BigUInt::exgcd_inverse(e, t);
	//std::cout << d.to_num_str(10) << std::endl;

	//BigUInt m = BigUInt::random_num({ 0 }, BigUInt::v_get_power_2_minus_1(256));
	//std::cout << m.to_num_str(16) << std::endl;

	//auto start = std::chrono::steady_clock::now();
	//BigUInt c = BigUInt::power_remainder(m, e, n);
	//BigUInt m_ = BigUInt::power_remainder(c, d, n);
	//auto end = std::chrono::steady_clock::now();
	//std::cout << std::chrono::duration_cast<
	//	std::chrono::milliseconds
	//>(end - start).count() << std::endl;
	//std::cout << m_.to_num_str(16) << std::endl;

	return 0;
}