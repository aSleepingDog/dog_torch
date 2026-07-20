#pragma once
#include <cstdint>
#include <array>
#include <string_view>

namespace dog_torch::utils
{
	template<size_t N>
	using tp_string = std::array<char, N>;

	template<size_t N>
	using tp_binary = std::array<uint8_t, N>;

	template<size_t N>
	consteval tp_string<N> from_c_str(const char(&s)[N])
	{
		tp_string<N> data = { 0 };
		std::copy(s, s + N, data.begin());
		return data;
	}

	template<uint8_t R>
	consteval size_t number_len(uint64_t n)
	{
		static_assert(R > 1, "Radix must not less than 1");
		if (n == 0)return 2;
		uint64_t len = 1;
		while (n != 0) { n /= 10; ++len; }
		return len;
	};

	template<uint64_t N, uint8_t R = 10, size_t L = number_len<R>(N)>
	consteval tp_string<L> from_uint64()
	{
		uint64_t n = N;
		tp_string<L> s;
		for (size_t i = L - 2; ; --i)
		{
			s[i] = static_cast<char>('0' + n % 10);
			n /= 10;
			if (i == 0)break;
		}
		s[L - 1] = '\0';
		return s;
	};

	template<size_t N1, size_t N2>
	constexpr tp_string<N1 + N2 - 1> operator+(tp_string<N1> s1, tp_string<N2> s2)
	{
		tp_string<N1 + N2 - 1> s;
		auto it = s.begin();
		for (uint64_t i = 0; i < N1 - 1; ++i)
		{
			*(it++) = s1.at(i);
		}
		for (uint64_t i = 0; i < N2; ++i)
		{
			*(it++) = s2.at(i);
		}
		return tp_string{ s };
	}

	template<size_t... N>
	consteval tp_string<((N - 1) + ...) + 1> concat(const tp_string<N>&... s)
	{
		tp_string<((N - 1) + ...) + 1> data = { 0 };
		auto it = data.begin();
		(
			(std::copy(s.begin(), s.end(), it), it += (N - 1))
			, ...);
		return data;
	};

	template <size_t N>
	constexpr std::string_view array_to_view(const tp_string<N>& arr)
	{
		return std::string_view(arr.data(), N - 1);
	}
}