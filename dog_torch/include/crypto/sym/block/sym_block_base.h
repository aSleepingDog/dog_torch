#pragma once
#include "export.h"

#include <iostream>
#include <functional>

#include "utils/ctrans.h"
#include "utils/compile.h"
#include "serialize/serialize.h"
#include "crypto/sym/sym_base.h"
#include "crypto/crypto_base.h"

namespace dog_torch::crypto::sym::block
{
	using PauseableChannel = dog_torch::async::thread::PauseableChannel;

	namespace algorithm
	{
		struct CPP_API Config
		{
			std::string name;
			std::string block_size_region;
			std::string key_size_region;
			Config(const std::string& name, const std::string& block_size_region, const std::string& key_size_region);
		};

		using extend_key_func = std::function<BinaryData(const BinaryData&, uint64_t, uint64_t)>;
		using block_self_cryption_func = std::function<void(BinaryData&, uint64_t, const BinaryData&, uint64_t)>;
		using block_cryption_func = std::function<BinaryData(const BinaryData&, uint64_t, const BinaryData&, uint64_t)>;

		class CPP_API Algorithm
		{
		protected:
			uint64_t block_size_;
			uint64_t key_size_;
		public:
			Algorithm(uint64_t block_size, uint64_t key_size);
			virtual ~Algorithm() = default;

			//static const Config& allowed_config();
			virtual Config config() const;
			virtual std::unique_ptr<Algorithm> clone() const;
			virtual std::string fmt_string() const;
			virtual Value serialize() const;

			virtual void set_block_size(uint64_t block_size);
			virtual void set_key_size(uint64_t key_size);
			virtual uint64_t get_block_size() const;
			virtual uint64_t get_key_size() const;

			virtual extend_key_func           get_extend_key() const;
			virtual block_cryption_func       get_encrypt() const;
			virtual block_cryption_func       get_decrypt() const;
			virtual block_self_cryption_func  get_encrypt_self() const;
			virtual block_self_cryption_func  get_decrypt_self() const;
		};
	}
	namespace padding
	{

		struct CPP_API Config
		{
			std::string name;
			std::string allowed_block_size_region;
			Config(const std::string& name, const std::string& allowed_block_size_region);
		};

		using padding_func = std::function<void(BinaryData&, uint64_t)>;

		struct CPP_API Padding
		{
			Padding() = default;

			Padding(const Padding& padding) = default;
			Padding& operator=(const Padding& padding) = default;
			Padding(Padding&& padding) noexcept = default;
			Padding& operator=(Padding&& padding) noexcept = default;

			virtual ~Padding() = default;

			virtual Config config() const;
			virtual std::unique_ptr<Padding> clone() const;
			virtual std::string fmt_string() const;
			virtual Value serialize() const;
			virtual bool check(uint64_t block_size) const;
			virtual padding_func get_padding() const;
			virtual padding_func get_unpadding() const;
		};

		struct CPP_API NoPadding : public Padding
		{
			static const Config& allowed_config();
			Config config() const override;
			std::unique_ptr<Padding> clone() const override;
			std::string fmt_string() const override;
			Value serialize() const override;
			bool check(uint64_t block_size) const override;
		    padding_func get_padding() const override;
			padding_func get_unpadding() const override;

		};
	}
	namespace mode
	{
		using crypt_func = std::function<BinaryData(const BinaryData&, const BinaryData&, const algorithm::Algorithm&)>;
		using stream_crypt_func = std::function<void(std::istream&, uint64_t, std::ostream&, const BinaryData&, const algorithm::Algorithm&)>;
		using streamp_crypt_func = std::function<void(PauseableChannel&, std::istream&, uint64_t, std::ostream&, const BinaryData&, const algorithm::Algorithm&)>;


		struct CPP_API Config
		{
			std::string name;
			std::map<std::string, ParamInfo> params;
			Config(const std::string& name, const std::map<std::string, ParamInfo> params);
			std::string fmt_string();
		};

		class CPP_API Mode
		{
		protected:
			std::unique_ptr<padding::Padding> padding_ = nullptr;
		public:
			Mode();

			Mode(const padding::Padding& padding);
			Mode(const std::unique_ptr<padding::Padding>& padding);
			Mode(std::unique_ptr<padding::Padding>&& padding);

			Mode(const Mode& other);
			Mode& operator=(const Mode& other);
			Mode(Mode&& other) noexcept;
			Mode& operator=(Mode&& other) noexcept;

			virtual ~Mode() = default;
			virtual std::unique_ptr<Mode> clone() const;

			static Config params_config();
			virtual Config config() const;
			virtual std::string fmt_string() const;
			virtual Value serialize() const;

			virtual bool set_uint64_param(const std::string& param, uint64_t value);
			virtual bool set_string_param(const std::string& param, const std::string& value);
			virtual bool set_binary_param(const std::string& param, const BinaryData& value);
			virtual bool set_padding(const padding::Padding& value);

			virtual bool check(const algorithm::Algorithm& algorithm) const;

			virtual crypt_func get_mult_encrypt() const;
			virtual crypt_func get_mult_decrypt() const;

			virtual stream_crypt_func get_stream_encrypt() const;
			virtual stream_crypt_func get_stream_decrypt() const;

			virtual streamp_crypt_func get_streamp_encrypt() const;
			virtual streamp_crypt_func get_streamp_decrypt() const;
		};
	}

	class CPP_API BlockCipher : public Cipher
	{
	private:
		BinaryData available_key_;
		std::unique_ptr<algorithm::Algorithm> algorithm_ = nullptr;
		std::unique_ptr<mode::Mode> mode_ = nullptr;
	public:
		BlockCipher();
		BlockCipher(const algorithm::Algorithm& algorithm, const mode::Mode& mode);
		BlockCipher(const BinaryData& key, const algorithm::Algorithm& algorithm, const mode::Mode& mode);
		std::unique_ptr<Cipher> clone() const override;
		~BlockCipher();

		void init() override;
		bool effective() const override;
		std::string fmt_string() const override;
		Value serialize() const override;
		algorithm::Algorithm& algorithm();
		const algorithm::Algorithm& const_algorithm() const;
		mode::Mode& mode();
		const mode::Mode& const_mode() const;

		BinaryData encrypt(const BinaryData& plain) override;
		BinaryData decrypt(const BinaryData& crypt) override;

		void encrypt_stream(std::istream& plain, uint64_t total, std::ostream& crypt) override;
		void decrypt_stream(std::istream& crypt, uint64_t total, std::ostream& plain) override;

		void encryptp_stream(PauseableChannel& pc, std::istream& plain, uint64_t total, std::ostream& crypt) override;
		void decryptp_stream(PauseableChannel& pc, std::istream& crypt, uint64_t total, std::ostream& plain) override;
	};

}

#define NS_ROOT(name) dog_torch__crypto__sym__block__##name
#define NS_ALG(name) dog_torch__crypto__sym__block__algorithm__##name
#define NS_MODE(name) dog_torch__crypto__sym__block__mode__##name
#define NS_PADDING(name) dog_torch__crypto__sym__block__padding__##name
#define CRYPTO_BASE(name) dog_torch__crypto__##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

extern "C"
{
	using NS_ROOT(Algorithm)    = dog_torch::crypto::sym::block::algorithm:: Algorithm;
	using NS_ALG(Config)        = dog_torch::crypto::sym::block::            algorithm::Config;
	using NS_ROOT(Mode)         = dog_torch::crypto::sym::block::mode::      Mode;
	using NS_MODE(Config)       = dog_torch::crypto::sym::block::            mode::Config;
	using NS_ROOT(Padding)      = dog_torch::crypto::sym::block::padding::   Padding;
	using NS_PADDING(Config)    = dog_torch::crypto::sym::block::            padding::Config;
	using NS_ROOT(BlockCipher)  = dog_torch::crypto::sym::block::            BlockCipher;

	C_API(UTILS(CppString)*)                  NS_ALG(Config_name)               (const LVALUE(NS_ALG(Config)) self);
	C_API(UTILS(CppString)*)                  NS_ALG(Config_block_region)       (const LVALUE(NS_ALG(Config)) self);
	C_API(UTILS(CppString)*)                  NS_ALG(Config_key_region)         (const LVALUE(NS_ALG(Config)) self);

	C_API(UTILS(CppString)*)                  NS_ROOT(Algorithm_fmt_string)     (const LVALUE(NS_ROOT(Algorithm)) self);
	C_API(void)                               NS_ROOT(Algorithm_delete)         (NS_ROOT(Algorithm)** self);

	C_API(UTILS(CppString)*)                  NS_MODE(Config_name)              (const LVALUE(NS_MODE(Config)) self);
	C_API(CRYPTO_BASE(ParamInfoTreeMap)*)     NS_MODE(Config_params)            (const LVALUE(NS_MODE(Config)) self);
	C_API(UTILS(CppString)*)                  NS_MODE(Mode_fmt_string)          (const LVALUE(NS_ROOT(Mode)) self);
	C_API(void)                               NS_ROOT(Mode_delete)              (NS_ROOT(Mode)** self);

	C_API(UTILS(CppString)*)                  NS_PADDING(Config_name)           (const LVALUE(NS_PADDING(Config)) self);
	C_API(UTILS(CppString)*)                  NS_PADDING(Config_block_region)   (const LVALUE(NS_PADDING(Config)) self);

	C_API(NS_ROOT(BlockCipher)*)              NS_ROOT(BlockCipher_create)       (LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(NS_ROOT(Algorithm)) alg, const LVALUE(NS_ROOT(Mode)) mode);
	C_API(void)                               NS_ROOT(BlockCipher_delete)       (NS_ROOT(BlockCipher)** self);
}

#undef NS_ROOT
#undef NS_ALG
#undef NS_MODE
#undef NS_PADDING
#undef CRYPTO_BASE
#undef SERIALIZE
#undef UTILS
