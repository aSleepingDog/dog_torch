#pragma once
#include "export.h"

#include <iostream>
#include <functional>

#include "serialize/serialize.h"
#include "crypto/sym/sym_base.h"
#include "crypto/sym/block/sym_block_base.h"
#include "async/thread/async_thread_base.h"
#include "serialize/stream.h"
#include "utils/tmp_macro.h"

namespace dog_torch::crypto::sym::block::mode
{
	class CPP_API OFB : public Mode
	{
	private:
		uint64_t shift_ = 0;
		BinaryData iv_;
	public:
		OFB(const BinaryData& iv, uint64_t shift, const padding::Padding& padding);
		OFB(const BinaryData& iv, const padding::Padding& padding);

		~OFB() override = default;

		OFB(const OFB& other);
		OFB& operator=(const OFB& other);
		OFB(OFB&& other) noexcept;
		OFB& operator=(OFB&& other) noexcept;

		std::unique_ptr<Mode> clone() const override;
		static const Config& params_config();
		Config config() const override;
		std::string fmt_string() const override;
		Value serialize() const override;

		bool set_uint64_param(const std::string& param, uint64_t value) override;
		bool set_string_param(const std::string& param, const std::string& value) override;
		bool set_binary_param(const std::string& param, const BinaryData& value) override;

		bool check(const algorithm::Algorithm& algorithm) const override;

		crypt_func get_mult_encrypt() const override;
		crypt_func get_mult_decrypt() const override;

		stream_crypt_func get_stream_encrypt() const override;
		stream_crypt_func get_stream_decrypt() const override;

		streamp_crypt_func get_streamp_encrypt() const override;
		streamp_crypt_func get_streamp_decrypt() const override;

		static BinaryData encrypt(
			const BinaryData& plain,
			const BinaryData& available_key,
			const algorithm::Algorithm& algorithm, padding::padding_func padding, const BinaryData& iv, uint64_t shift
		);
		static BinaryData decrypt(
			const BinaryData& crypt,
			const BinaryData& available_key,
			const algorithm::Algorithm& algorithm, padding::padding_func unpadding, const BinaryData& iv, uint64_t shift
		);
		static void encrypt_stream(
			std::istream& plain, uint64_t total, std::ostream& crypt,
			const BinaryData& available_key,
			const algorithm::Algorithm& algorithm, padding::padding_func padding, const BinaryData& iv, uint64_t shift
		);
		static void decrypt_stream(
			std::istream& crypt, uint64_t total, std::ostream& plain,
			const BinaryData& available_key,
			const algorithm::Algorithm& algorithm, padding::padding_func unpadding, const BinaryData& iv, uint64_t shift
		);
		static void encryptp_stream(
			PauseableChannel& pc,
			std::istream& plain, uint64_t total, std::ostream& crypt,
			const BinaryData& available_key,
			const algorithm::Algorithm& algorithm, padding::padding_func padding, const BinaryData& iv, uint64_t shift
		);
		static void decryptp_stream(
			PauseableChannel& pc,
			std::istream& crypt, uint64_t total, std::ostream& plain,
			const BinaryData& available_key,
			const algorithm::Algorithm& algorithm, padding::padding_func unpadding, const BinaryData& iv, uint64_t shift
		);
	};

	class OFBb : public Mode
	{
	private:
		uint64_t shift_ = 0;
		BinaryData iv_;
	public:
		OFBb(const BinaryData& iv, const padding::Padding& padding);
		OFBb(const BinaryData& iv, uint64_t shift, const padding::Padding& padding);

		~OFBb() override = default;

		OFBb(const OFBb& other);
		OFBb& operator=(const OFBb& other);
		OFBb(OFBb&& other) noexcept;
		OFBb& operator=(OFBb&& other) noexcept;

		std::unique_ptr<Mode> clone() const override;
		static const Config& params_config();
		Config config() const override;
		std::string fmt_string() const override;
		Value serialize() const override;

		bool set_uint64_param(const std::string& param, uint64_t value) override;
		bool set_string_param(const std::string& param, const std::string& value) override;
		bool set_binary_param(const std::string& param, const BinaryData& value) override;

		bool check(const algorithm::Algorithm& algorithm) const override;

		crypt_func get_mult_encrypt() const override;
		crypt_func get_mult_decrypt() const override;

		stream_crypt_func get_stream_encrypt() const override;
		stream_crypt_func get_stream_decrypt() const override;

		streamp_crypt_func get_streamp_encrypt() const override;
		streamp_crypt_func get_streamp_decrypt() const override;

		static BinaryData encrypt(
			const BinaryData& plain,
			const BinaryData& available_key,
			const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift
		);
		static BinaryData decrypt(
			const BinaryData& crypt,
			const BinaryData& available_key,
			const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift
		);
		static void encrypt_stream(
			std::istream& plain, uint64_t total, std::ostream& crypt,
			const BinaryData& available_key,
			const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift
		);
		static void decrypt_stream(
			std::istream& crypt, uint64_t total, std::ostream& plain,
			const BinaryData& available_key,
			const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift
		);
		static void encryptp_stream(
			PauseableChannel& pc,
			std::istream& plain, uint64_t total, std::ostream& crypt,
			const BinaryData& available_key,
			const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift
		);
		static void decryptp_stream(
			PauseableChannel& pc,
			std::istream& crypt, uint64_t total, std::ostream& plain,
			const BinaryData& available_key,
			const algorithm::Algorithm& algorithm, const BinaryData& iv, uint64_t shift
		);
	};

}