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
	class CPP_API GCM : public Mode
	{
	private:
		uint64_t shift_ = 0;
		uint64_t tag_out_ = 0;
		BinaryData aad_;
		BinaryData iv_;
	public:
		GCM(const BinaryData& iv, uint64_t shift, const padding::Padding& padding, const BinaryData& a, uint64_t tag_out);

		~GCM() override = default;

		GCM(const GCM& other);
		GCM& operator=(const GCM& other);
		GCM(GCM&& other) noexcept;
		GCM& operator=(GCM&& other) noexcept;

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

		static void incr(BinaryData& conter, uint64_t s_bit);
		static BinaryData mult(const BinaryData& x, const BinaryData& y);
		static BinaryData GHASH(const BinaryData& h, const BinaryData& x);
		static uint64_t fill_size(uint64_t l);

		static BinaryData encrypt(
			const BinaryData& plain,
			const BinaryData& available_key,
			const algorithm::Algorithm& algorithm, padding::padding_func padding,
			const BinaryData& iv, uint64_t shift, const BinaryData& acc, uint64_t tag_out
		);
		static BinaryData decrypt(
			const BinaryData& crypt,
			const BinaryData& available_key,
			const algorithm::Algorithm& algorithm, padding::padding_func unpadding,
			const BinaryData& iv, uint64_t shift, const BinaryData& acc, uint64_t tag_out
		);

		static void encrypt_stream(
			std::istream& plain, uint64_t total, std::ostream& crypt,
			const BinaryData& available_key,
			const algorithm::Algorithm& algorithm, padding::padding_func padding,
			const BinaryData& iv, uint64_t shift, const BinaryData& acc, uint64_t tag_out
		);
		static void decrypt_stream(
			std::istream& crypt, uint64_t total, std::ostream& plain,
			const BinaryData& available_key,
			const algorithm::Algorithm& algorithm, padding::padding_func unpadding,
			const BinaryData& iv, uint64_t shift, const BinaryData& acc, uint64_t tag_out
		);
		static void encryptp_stream(
			PauseableChannel& pc,
			std::istream& plain, uint64_t total, std::ostream& crypt,
			const BinaryData& available_key,
			const algorithm::Algorithm& algorithm, padding::padding_func padding,
			const BinaryData& iv, uint64_t shift, const BinaryData& acc, uint64_t tag_out
		);
		static void decryptp_stream(
			PauseableChannel& pc,
			std::istream& crypt, uint64_t total, std::ostream& plain,
			const BinaryData& available_key,
			const algorithm::Algorithm& algorithm, padding::padding_func unpadding,
			const BinaryData& iv, uint64_t shift, const BinaryData& acc, uint64_t tag_out
		);
	};
}