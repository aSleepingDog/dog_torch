#pragma once
#include "export.h"

#include <iostream>
#include <functional>

#include "utils/ctrans.h"
#include "utils/compile.h"
#include "serialize/serialize.h"
#include "crypto/crypto_base.h"

namespace dog_torch::crypto::asym
{
	using BinaryData = dog_torch::serialize::BinaryData;
	using Value = dog_torch::serialize::tlv::Value;

	struct KeyPair
	{
		BinaryData public_key;
		BinaryData private_key;
		KeyPair() = default;
		KeyPair(const BinaryData& public_key, const BinaryData& private_key);
	};

	namespace algorithm
	{
		struct Config
		{
			std::string name;
			std::string key_size_region;
			std::map<std::string, ParamInfo> params;
			Config(const std::string& name, const std::string& key_size_region, const std::map<std::string, ParamInfo>& params);
		};

		using crypt_func = std::function<BinaryData(const BinaryData&, const BinaryData&)>;

		struct Algorithm
		{
			uint64_t key_size;
			Algorithm(uint64_t key_size);

			virtual Config get_config() const;
			virtual KeyPair generate_key_pair() const;
			virtual crypt_func get_encrypt_func() const;
			virtual crypt_func get_decrypt_func() const;

			virtual ~Algorithm();

			virtual std::unique_ptr<Algorithm> clone() const;

		};
	}

	namespace padding
	{
		using padding_func = std::function<BinaryData(const BinaryData&)>;

		struct Config
		{
			std::string name;
			std::map<std::string, ParamInfo> params;
			std::map<std::string, PrimusType> primuses;
			Config(const std::string& name, const std::map<std::string, ParamInfo>& params, std::map<std::string, PrimusType> primuses);
		};

		struct Padding
		{
			virtual Config get_config() const;
			virtual std::unique_ptr<Padding> clone() const;

			virtual bool check(const algorithm::Algorithm& alg);
			virtual padding_func get_padding() const;
			virtual padding_func get_unpadding() const;

			virtual ~Padding();
		};

		struct NoPadding : public Padding
		{
			static const Config& get_allow_config();
			Config get_config() const override;
			std::unique_ptr<Padding> clone() const override;

			bool check(const algorithm::Algorithm& alg) override;
			static BinaryData none(const BinaryData& data);
			padding_func get_padding() const override;
			padding_func get_unpadding() const override;
		};
	}

	class CPP_API Cipher
	{
	protected:
		bool is_effective_ = false;
		std::unique_ptr<algorithm::Algorithm> alg_p_;
		std::unique_ptr<padding::Padding> pad_p_;
		KeyPair key_pair_;
	public:
		Cipher(const algorithm::Algorithm& alg, const padding::Padding& pad);
		Cipher(const KeyPair& key_pair, const algorithm::Algorithm& alg, const padding::Padding& pad);

		Cipher(const Cipher& other);
		Cipher& operator=(const Cipher& other);
		Cipher(Cipher&& other) noexcept;
		Cipher& operator=(Cipher&& other) noexcept;

		void init();
		bool effective() const;
		void set_key(const KeyPair& key_pair);
		void init_key();
		KeyPair key_pair() const;
		std::string fmt_string() const;

		BinaryData encrypt(const BinaryData& plain);
		BinaryData decrypt(const BinaryData& crypt);
	};

}
