#pragma once
#include "export.h"

#include <iostream>
#include <functional>

#include "utils/ctrans.h"
#include "utils/compile.h"
#include "serialize/serialize.h"
#include "crypto/sym/sym_base.h"

namespace dog_torch::crypto::sym::stream
{
	using PauseableChannel = dog_torch::async::thread::PauseableChannel;

	namespace algorithm
	{
		struct Config
		{
			std::string name;
			std::string effective_region;
			std::string key_size_region;
			Config(const std::string& name, const std::string& effective_region, const std::string& key_size_region);
		};

		using UpdateFunc = std::function<BinaryData(const BinaryData&)>;
		using CombineFunc = std::function<void(BinaryData&, const BinaryData&)>;

		class Algorithm
		{
		protected:
			bool is_initialized_ = false;
			uint64_t effective_;
			uint64_t key_size_;
		public:
			Algorithm(uint64_t effective, uint64_t key_size);

			Algorithm(const Algorithm& other);
			Algorithm& operator=(const Algorithm& other);
			Algorithm(Algorithm&& other) noexcept;
			Algorithm& operator=(Algorithm&& other) noexcept;
			virtual std::unique_ptr<algorithm::Algorithm> clone() const;

			~Algorithm();

			virtual Config config() const;
			virtual void init();
			virtual uint64_t updata_size() const;
			virtual UpdateFunc update_func();
			virtual CombineFunc combine_func();
			virtual std::string fmt_string() const;
			virtual Value serialize() const;

			static void XOR_combine(BinaryData& dst, const BinaryData& src);
		};
	};

	class StreamCipher : public Cipher
	{
	private:
		std::unique_ptr<algorithm::Algorithm> alg_;
		bool is_bit_ = false;
		uint64_t shift_ = 0;
	public:
		StreamCipher(const algorithm::Algorithm& alg, uint64_t shift = 0, bool is_bit = false);

		void init() override;
		bool effective() const override;
		std::string fmt_string() const override;
		Value serialize() const override;

		BinaryData encrypt(const BinaryData& plain) override;
		BinaryData decrypt(const BinaryData& crypt) override;

		void encrypt_stream(std::istream& plain, uint64_t total, std::ostream& crypt) override;
		void decrypt_stream(std::istream& crypt, uint64_t total, std::ostream& plain) override;

		void encryptp_stream(PauseableChannel& pc, std::istream& plain, uint64_t total, std::ostream& crypt) override;
		void decryptp_stream(PauseableChannel& pc, std::istream& crypt, uint64_t total, std::ostream& plain) override;
	};
}

#define NS_ROOT(name) dog_torch__crypto__sym__stream__##name
#define NS_ALG(name) dog_torch__crypto__sym__stream__algorithm__##name
#define UTILS(name)  dog_torch__utils__##name

extern "C"
{
	using NS_ROOT(Algorithm)      = dog_torch::crypto::sym::stream::algorithm::Algorithm;
	using NS_ALG(Config)          = dog_torch::crypto::sym::stream::algorithm::Config;
	using NS_ROOT(StreamCipher)   = dog_torch::crypto::sym::stream::StreamCipher;

	C_API(UTILS(CppString)*)                  NS_ALG(Config_name)               (const LVALUE(NS_ALG(Config)) self);
	C_API(UTILS(CppString)*)                  NS_ALG(Config_effective_region)   (const LVALUE(NS_ALG(Config)) self);
	C_API(UTILS(CppString)*)                  NS_ALG(Config_key_region)         (const LVALUE(NS_ALG(Config)) self);

	C_API(UTILS(CppString)*)                  NS_ROOT(Algorithm_fmt_string)     (const LVALUE(NS_ROOT(Algorithm)) self);
	C_API(void)                               NS_ROOT(Algorithm_delete)         (NS_ROOT(Algorithm)** self);

	C_API(NS_ROOT(StreamCipher)*)             NS_ROOT(StreamCipher_create)       (LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(NS_ROOT(Algorithm)) alg, uint64_t shift, uint8_t is_bit);
	C_API(void)                               NS_ROOT(StreamCipher_delete)       (NS_ROOT(StreamCipher)** self);

}

#undef NS_ROOT
#undef NS_ALG
#undef UTILS