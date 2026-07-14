#pragma once
#include "export.h"

#include <iostream>
#include <functional>

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
		StreamCipher(const BinaryData& key, const algorithm::Algorithm& alg, uint64_t shift = 0, bool is_bit = false);

		void init() override;
		bool effective() const override;

		BinaryData encrypt(const BinaryData& plain) override;
		BinaryData decrypt(const BinaryData& crypt) override;

		void encrypt_stream(std::istream& plain, uint64_t total, std::ostream& crypt) override;
		void decrypt_stream(std::istream& crypt, uint64_t total, std::ostream& plain) override;

		void encryptp_stream(PauseableChannel& pc, std::istream& plain, uint64_t total, std::ostream& crypt) override;
		void decryptp_stream(PauseableChannel& pc, std::istream& crypt, uint64_t total, std::ostream& plain) override;
	};
}