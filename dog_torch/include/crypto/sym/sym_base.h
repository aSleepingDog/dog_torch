#pragma once
#include "export.h"

#include <iostream>
#include <functional>

#include "utils/ctrans.h"
#include "serialize/serialize.h"
#include "async/thread/async_thread_base.h"

namespace dog_torch::crypto::sym
{
	using BinaryData = dog_torch::serialize::BinaryData;
	using Value = dog_torch::serialize::tlv::Value;
	using PauseableChannel = dog_torch::async::thread::PauseableChannel;

	class DOG_TORCH_API Cipher
	{
	protected:
		bool is_effective_ = false;
		BinaryData ori_key_;
	public:
		Cipher();
		Cipher(const BinaryData& key);
		virtual ~Cipher();
		virtual std::unique_ptr<Cipher> clone() const;

		virtual void init();
		virtual bool effective() const;
		virtual void set_key(const BinaryData& key);
		virtual BinaryData key() const;
		virtual std::string fmt_string() const;
		virtual Value serialize() const;

		virtual BinaryData encrypt(const BinaryData& plain);
		virtual BinaryData decrypt(const BinaryData& crypt);

		virtual void encrypt_stream(std::istream& plain, uint64_t total, std::ostream& crypt);
		virtual void decrypt_stream(std::istream& crypt, uint64_t total, std::ostream& plain);

		virtual void encryptp_stream(PauseableChannel& pc, std::istream& plain, uint64_t total, std::ostream& crypt);
		virtual void decryptp_stream(PauseableChannel& pc, std::istream& crypt, uint64_t total, std::ostream& plain);
		static void cryptp_stream_with(PauseableChannel& pc, Cipher& self, std::istream& input, uint64_t total, std::ostream& output);

	};

}

#ifdef SHARED
#include "async/pool/pool.h"
namespace dog_torch::async::pool
{
	using cryptp_stream_func = std::function<void(PauseableChannel&, dog_torch::crypto::sym::Cipher&, std::istream&, uint64_t, std::ostream&)>;
	template<> Result<void> PausedThreadPool::add_task(cryptp_stream_func&&, dog_torch::crypto::sym::Cipher&, std::istream&, uint64_t&&, std::ostream&);
};
#endif // SHARED

#define NAMESPACE(name) dog_torch__crypto__sym__##name
#define CRYPTO_BASE(name) dog_torch__crypto__##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

extern "C"
{
	using NAMESPACE(Cipher) = dog_torch::crypto::sym::Cipher;

	C_API(void)                       NAMESPACE(Cipher_init)                (LVALUE(UTILS(CppResultSet)) result_set, LVALUE(NAMESPACE(Cipher)) self);
	C_API(uint8_t)                    NAMESPACE(Cipher_effective)           (const LVALUE(NAMESPACE(Cipher)) self);
	C_API(SERIALIZE(BinaryData)*)     NAMESPACE(Cipher_key)                 (const LVALUE(NAMESPACE(Cipher)) self);
	C_API(void)                       NAMESPACE(Cipher_set_key)             (LVALUE(NAMESPACE(Cipher)) self, const LVALUE(SERIALIZE(BinaryData)) key);

	C_API(SERIALIZE(BinaryData)*)     NAMESPACE(Cipher_encrypt)             (LVALUE(UTILS(CppResultSet)) result_set, LVALUE(NAMESPACE(Cipher)) self, const LVALUE(SERIALIZE(BinaryData)) plain);
	C_API(SERIALIZE(BinaryData)*)     NAMESPACE(Cipher_decrypt)             (LVALUE(UTILS(CppResultSet)) result_set, LVALUE(NAMESPACE(Cipher)) self, const LVALUE(SERIALIZE(BinaryData)) crypt);

	C_API(void)                       NAMESPACE(Cipher_encrypt_stream)      (LVALUE(UTILS(CppResultSet)) result_set, LVALUE(NAMESPACE(Cipher)) self, const LVALUE(UTILS(CppString)) plain, uint64_t total, const LVALUE(UTILS(CppString)) crypt);
	C_API(void)                       NAMESPACE(Cipher_decrypt_stream)      (LVALUE(UTILS(CppResultSet)) result_set, LVALUE(NAMESPACE(Cipher)) self, const LVALUE(UTILS(CppString)) crypt, uint64_t total, const LVALUE(UTILS(CppString)) plain);

}

#undef NAMESPACE
#undef CRYPTO_BASE
#undef SERIALIZE
#undef UTILS
