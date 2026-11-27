#include "math/math.h"
#include "serialize/serialize.h"

#include "crypto/hash/hash_algorithms.h"

#include "crypto/sym/stream/sym_stream_algorithms.h"

#include "crypto/sym/block/sym_block_algorithms.h"
#include "crypto/sym/block/sym_block_modes.h"
#include "crypto/sym/block/sym_block_paddings.h"

#include <random>

class ZeroBuffer : public std::basic_streambuf<char>
{
public:
	ZeroBuffer() = default;

	int_type underflow() override
	{
		return 0;
	}

	int_type uflow() override
	{
		return 0;
	}

	std::streamsize xsgetn(char_type* s, std::streamsize count) override
	{
		memset(s, 0, count);
		return count;
	}

	std::streamsize showmanyc() override
	{
		return std::numeric_limits<std::streamsize>::max();
	}
};

using dog_torch::serialize::BinaryData;
using dog_torch::math::region::NumberIterator;

using dog_torch::crypto::Param;

uint64_t random_uint64()
{
	std::random_device rd;
	uint64_t r = 0;
	r = rd();
	r <<= 32;
	r |= rd();
	return r;
}

class ZeroStream : public std::istream
{
	ZeroBuffer rb = ZeroBuffer();
public:
	ZeroStream() : std::istream(&rb) {}
};

class EmptyStream : public std::ostream
{
	dog_torch::serialize::EmptyBuffer eb;
public:
	EmptyStream() : std::ostream(&eb) {};
};

class AutoClock
{
	std::chrono::steady_clock::time_point start;
	uint64_t* time = nullptr;

public:
	AutoClock(uint64_t* time) : time(time), start(std::chrono::steady_clock::now()) {};
	~AutoClock()
	{
		if (time == nullptr) return;
		*time = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();
	}
};
uint64_t base = 0;
void showing(const std::string& config, uint64_t total, uint64_t time)
{
	std::cout << "[operator]" << std::endl;
	std::cout << config << std::endl;
	std::cout << "[total]" << std::endl;
	std::cout << total << std::endl;
	std::cout << "[time]" << std::endl;
	if (time > base)
	{
		time -= base;
		std::cout << time << std::endl;
	}
	else
	{
		std::cout << time << "=> 1" << std::endl;
		time = 1;
	}
	std::cout << "[speed]" << std::endl;
	std::cout << (((1.0 * total) / (1024 * 1024)) / (1.0 * time / (1000 * 1000))) << " MB/s" << std::endl;
	std::cout << std::endl;
}

int main()
{
	uint64_t total = 1024 * 1024 * 1;

	ZeroStream input;
	EmptyStream output;

	{
		AutoClock ac(&base);
		char buffer[16];
		for (uint64_t i = 0; i < total / 16; ++i)
		{
			input.read(buffer, 16);
			output.write(buffer, 16);
		}
	}

	for (auto& config : dog_torch::crypto::hash::algorithm::get_all())
	{
		using dog_torch::crypto::hash::Generator;
		using dog_torch::crypto::hash::algorithm::create;
		NumberIterator nit = NumberIterator(config.get().region);
		while (nit.has_next())
		{
			uint64_t number = nit.next();
			Generator gen(create(config.get().name, number, {}));
			uint64_t time = 0;
			try
			{
				AutoClock ac(&time);
				gen.calculate(input, total);
			}
			catch(...){}
			showing(gen.fmt_string(), total, time);
		}
	}
	auto bin = BinaryData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", BinaryData::Type::Hex);

	for (auto& config : dog_torch::crypto::sym::stream::algorithm::get_all())
	{
		using dog_torch::crypto::sym::stream::StreamCipher;
		using dog_torch::crypto::sym::stream::algorithm::create;

		NumberIterator enit = NumberIterator(config.get().effective_region);
		while (enit.has_next())
		{
			NumberIterator knit = NumberIterator(config.get().key_size_region);
			while (knit.has_next())
			{
				uint64_t effi = enit.next();
				uint64_t key_s = knit.next();

				StreamCipher cipher(*create(config.get().name, effi, key_s));
				uint64_t time = 0;
				cipher.set_key(bin);
				cipher.init();
				try
				{
					AutoClock ac(&time);
					cipher.encrypt_stream(input, total, output);
				}
				catch (...) {}
				showing(cipher.fmt_string() + ":encrypt", total, time);
				try
				{
					AutoClock ac(&time);
					cipher.decrypt_stream(input, total, output);
				}
				catch (...) {}
				showing(cipher.fmt_string() + ":decrypt", total, time);
			}
		}
	}


	std::unordered_map<std::string, Param> params;
	params["iv"] = bin;
	params["shift"] = 0ULL;

	for (auto& config : dog_torch::crypto::sym::block::algorithm::get_all())
	{
		using dog_torch::crypto::sym::block::BlockCipher;
		using dog_torch::crypto::sym::block::padding::PKCS7;
		auto algorithm_create = [](const std::string& name, uint64_t b, uint64_t k)
			{
				return dog_torch::crypto::sym::block::algorithm::create(name, b, k);
			};
		NumberIterator bnit = NumberIterator(config.get().block_size_region);
		while (bnit.has_next())
		{
			NumberIterator knit = NumberIterator(config.get().key_size_region);
			uint64_t block_s = bnit.next();
			while (knit.has_next())
			{
				uint64_t key_s = knit.next();

				auto alg_p = algorithm_create(config.get().name, block_s, key_s);

				for (auto& mode : dog_torch::crypto::sym::block::mode::get_all())
				{
					auto mode_p = dog_torch::crypto::sym::block::mode::create(mode.get().name, PKCS7(), params);

					BlockCipher cipher(*alg_p, *mode_p);
					uint64_t time = 0;
					cipher.set_key(bin);
					cipher.init();
					try
					{
						AutoClock ac(&time);
						cipher.encrypt_stream(input, total, output);
					}
					catch (...) {}
					showing(cipher.fmt_string() + ":encrypt", total, time);
					try
					{
						AutoClock ac(&time);
						cipher.decrypt_stream(input, total, output);
					}
					catch (...) {}
					showing(cipher.fmt_string() + ":decrypt", total, time);
				}

			}
		}
	}
}