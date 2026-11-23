#pragma once
#include "export.h"

#include <iostream>
#include <functional>

#include "utils/ctrans.h"
#include "serialize/serialize.h"
#include "crypto/crypto_base.h"

namespace dog_torch::crypto::sym
{
	class CPP_API Cipher
	{
	protected:
		bool is_effective_ = false;
		BinaryData ori_key_;
	public:
		Cipher();
		Cipher(const BinaryData& key);
		virtual ~Cipher();
		virtual std::unique_ptr<Cipher> clone() const = 0;

		virtual void init() = 0;
		virtual bool effective() const;
		virtual void set_key(const BinaryData& key);
		virtual BinaryData key() const;
		virtual std::string fmt_string() const = 0;
		virtual Value serialize() const = 0;

		virtual BinaryData encrypt(const BinaryData& plain) = 0;
		virtual BinaryData decrypt(const BinaryData& crypt) = 0;

		virtual void encrypt_stream(std::istream& plain, uint64_t total, std::ostream& crypt, std::function<uint8_t(uint64_t, uint64_t)> onRunning = alwaysRunning) = 0;
		virtual void decrypt_stream(std::istream& crypt, uint64_t total, std::ostream& plain, std::function<uint8_t(uint64_t, uint64_t)> onRunning = alwaysRunning) = 0;
	};

}

#if defined(EN_C_API)
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
#endif