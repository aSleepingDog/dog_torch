#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rsa.h>

#include "crypto/asym/algorithms/RSA.h"
#include "crypto/asym/paddings/OAEP.h"
#include "crypto/hash/algorithms/SHA2.h"
#include "serialize/asn1.h"
#include "serialize/BinaryData.h"

using dog_torch::serialize::BinaryData;
using dog_torch::serialize::asn1::Value;
using dog_torch::crypto::asym::KeyPair;
// NOTE: do NOT do `using ...::algorithm::RSA` here — it would collide with
// OpenSSL's global `RSA` struct type. Use the DTRSA alias for dog_torch's RSA.
using DTRSA = dog_torch::crypto::asym::algorithm::RSA;
using dog_torch::crypto::asym::padding::OAEP;
using dog_torch::crypto::hash::algorithm::SHA2;

// suppress OpenSSL 3.0 deprecation warnings for the low-level RSA API
#ifdef _MSC_VER
#pragma warning(disable : 4996)
#endif

static void print_openssl_error(const char* what)
{
	std::cerr << "[OpenSSL ERROR] " << what << std::endl;
	ERR_print_errors_fp(stderr);
}

// dog_torch DTRSA::decrypt() strips leading zero bytes from the recovered message.
// The OAEP encoded message starts with a mandatory 0x00 byte, so after raw RSA
// decryption we must left-pad the result back to (k - 1) bytes (maskedSeed || maskedDB)
// before feeding it to OAEP unpadding.
static BinaryData left_pad_to(const BinaryData& data, uint64_t target_len)
{
	if (data.size() >= target_len)
		return data;
	BinaryData result(target_len);
	std::copy(data.cbegin(), data.cend(), result.begin() + (target_len - data.size()));
	return result;
}

// dog_torch always appends an empty SEQUENCE as otherPrimeInfos in RSAPrivateKey,
// but for version = twoPrime(0) the field must be absent. Strip it so OpenSSL's
// d2i_RSAPrivateKey accepts the key.
static BinaryData normalize_rsa_private_key(const BinaryData& der)
{
	auto pos = der.cbegin();
	Value v = Value::parse(pos, der.cend());
	auto& seq = v.to_sequence();
	if (seq.size() == 10 && seq[9].type() == dog_torch::serialize::asn1::Type::Sequence
		&& seq[9].to_sequence().empty())
	{
		seq.pop_back();
	}
	return BinaryData(v.serialize());
}

// run the full RSA comparison suite for a single (key_size, pub_exp) combination.
// returns the number of failed checks for this case.
static uint64_t run_rsa_case(uint64_t key_size, uint32_t pub_exp)
{
	uint64_t error = 0;
	const uint64_t k = key_size / 8; // modulus size in bytes
	const uint64_t hlen = 32;        // SHA-256 output size

	std::cout << "\n##################################################" << std::endl;
	std::cout << "# RSA case: key_size = " << key_size << " bits, e = " << pub_exp << std::endl;
	std::cout << "##################################################" << std::endl;

	// ------------------------------------------------------------------
	// 1. Generate RSA key pair with dog_torch
	// ------------------------------------------------------------------
	DTRSA alg(key_size, pub_exp);
	KeyPair key_pair = alg.generate_key_pair();
	std::cout << "[dog_torch] key pair generated." << std::endl;

	// ------------------------------------------------------------------
	// 2. Load dog_torch keys into OpenSSL (PKCS#1 DER format)
	// ------------------------------------------------------------------
	BinaryData pub_der = key_pair.public_key;
	BinaryData priv_der = normalize_rsa_private_key(key_pair.private_key);

	const unsigned char* pub_ptr = reinterpret_cast<const unsigned char*>(pub_der.data_ptr());
	RSA* ossl_pub = d2i_RSAPublicKey(NULL, &pub_ptr, (long)pub_der.size());
	if (!ossl_pub)
	{
		print_openssl_error("d2i_RSAPublicKey failed");
		return 1;
	}

	const unsigned char* priv_ptr = reinterpret_cast<const unsigned char*>(priv_der.data_ptr());
	RSA* ossl_priv = d2i_RSAPrivateKey(NULL, &priv_ptr, (long)priv_der.size());
	if (!ossl_priv)
	{
		print_openssl_error("d2i_RSAPrivateKey failed");
		RSA_free(ossl_pub);
		return 1;
	}

	std::cout << "[OpenSSL] loaded dog_torch public/private keys (PKCS#1 DER compatible)." << std::endl;

	// Wrap the RSA objects into EVP_PKEY for OAEP operations.
	// EVP_PKEY_assign_RSA transfers ownership of the RSA* to the EVP_PKEY.
	EVP_PKEY* evp_pub = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(evp_pub, ossl_pub);
	EVP_PKEY* evp_priv = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(evp_priv, ossl_priv);

	// ------------------------------------------------------------------
	// 3. Raw RSA (no padding) - deterministic, compare byte-for-byte
	// ------------------------------------------------------------------
	std::cout << "\n--- Raw RSA (no padding) ---" << std::endl;
	{
		// Build a k-byte message whose numeric value is guaranteed < n
		// (leading byte 0x00) AND large enough that m^e >= n even for e=3,
		// so modular exponentiation is actually exercised.
		BinaryData msg(k);
		for (uint64_t i = 1; i < k; ++i)
			msg[i] = (uint8_t)((i * 7 + 1) % 251 + 1); // non-zero deterministic pattern

		// --- encrypt ---
		BinaryData dt_ct = DTRSA::encrypt(msg, key_pair.public_key, key_size);

		std::vector<unsigned char> ossl_ct_buf(RSA_size(ossl_pub));
		int r = RSA_public_encrypt(
			(int)msg.size(),
			reinterpret_cast<const unsigned char*>(msg.data_ptr()),
			ossl_ct_buf.data(), ossl_pub, RSA_NO_PADDING);
		if (r < 0)
		{
			print_openssl_error("RSA_public_encrypt(NO_PADDING) failed");
			error++;
		}
		else
		{
			BinaryData ossl_ct(std::vector<uint8_t>(ossl_ct_buf.begin(), ossl_ct_buf.end()));
			if (dt_ct == ossl_ct)
				std::cout << "[PASS] raw encrypt: dog_torch == OpenSSL" << std::endl;
			else
			{
				std::cout << "[FAIL] raw encrypt: ciphertext mismatch" << std::endl;
				error++;
			}
		}

		// --- decrypt (OpenSSL decrypts dog_torch ciphertext) ---
		std::vector<unsigned char> dec_buf(RSA_size(ossl_priv));
		r = RSA_private_decrypt(
			(int)dt_ct.size(),
			reinterpret_cast<const unsigned char*>(dt_ct.data_ptr()),
			dec_buf.data(), ossl_priv, RSA_NO_PADDING);
		if (r < 0)
		{
			print_openssl_error("RSA_private_decrypt(NO_PADDING) failed");
			error++;
		}
		else
		{
			BinaryData dec(std::vector<uint8_t>(dec_buf.begin(), dec_buf.end()));
			auto first_nonzero = [](const BinaryData& b) {
				return std::find_if(b.cbegin(), b.cend(), [](uint8_t x) { return x != 0; });
			};
			BinaryData dec_stripped = dec.sub_bytes_pos(first_nonzero(dec), dec.cend());
			BinaryData msg_stripped = msg.sub_bytes_pos(first_nonzero(msg), msg.cend());
			if (dec_stripped == msg_stripped)
				std::cout << "[PASS] raw decrypt: OpenSSL decrypt(dog_torch ct) == msg" << std::endl;
			else
			{
				std::cout << "[FAIL] raw decrypt: plaintext mismatch" << std::endl;
				error++;
			}
		}

		// --- decrypt (dog_torch decrypts OpenSSL ciphertext) ---
		BinaryData ossl_ct(std::vector<uint8_t>(ossl_ct_buf.begin(), ossl_ct_buf.end()));
		BinaryData dt_dec = DTRSA::decrypt(ossl_ct, key_pair.private_key, key_size);
		BinaryData dt_dec_stripped = dt_dec.sub_bytes_pos(
			std::find_if(dt_dec.cbegin(), dt_dec.cend(), [](uint8_t x) { return x != 0; }),
			dt_dec.cend());
		BinaryData msg_stripped = msg.sub_bytes_pos(
			std::find_if(msg.cbegin(), msg.cend(), [](uint8_t x) { return x != 0; }),
			msg.cend());
		if (dt_dec_stripped == msg_stripped)
			std::cout << "[PASS] raw decrypt: dog_torch decrypt(OpenSSL ct) == msg" << std::endl;
		else
		{
			std::cout << "[FAIL] raw decrypt: dog_torch could not recover OpenSSL plaintext" << std::endl;
			error++;
		}
	}

	// ------------------------------------------------------------------
	// 4. OAEP (SHA-256, empty label) cross-compatibility
	//    skipped when the key is too small for OAEP-SHA256 (k < 2*hlen + 2).
	// ------------------------------------------------------------------
	std::cout << "\n--- OAEP (SHA-256, empty label) ---" << std::endl;
	if (k < 2 * hlen + 2)
	{
		std::cout << "[SKIP] key too small for OAEP-SHA256 (k=" << k
				  << " < 2*hlen+2=" << (2 * hlen + 2) << ")" << std::endl;
	}
	else
	{
		OAEP oaep(SHA2(256), key_size, BinaryData("", BinaryData::Type::UTF8));
		BinaryData plain{ "Hello world!", BinaryData::Type::UTF8 };

		// 4a. dog_torch encrypt -> OpenSSL decrypt
		{
			BinaryData padded = oaep.get_padding()(plain);
			BinaryData dt_ct = DTRSA::encrypt(padded, key_pair.public_key, key_size);

			EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(evp_priv, NULL);
			bool ok = ctx && EVP_PKEY_decrypt_init(ctx) > 0;
			if (ok)
			{
				EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
				EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
				EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
				EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, NULL, 0);

				std::vector<unsigned char> out(k);
				size_t outlen = out.size();
				if (EVP_PKEY_decrypt(ctx, out.data(), &outlen,
						reinterpret_cast<const unsigned char*>(dt_ct.data_ptr()),
						dt_ct.size()) <= 0)
				{
					print_openssl_error("EVP_PKEY_decrypt(OAEP) failed");
					error++;
				}
				else
				{
					BinaryData recovered(std::vector<uint8_t>(out.begin(), out.begin() + outlen));
					if (recovered == plain)
						std::cout << "[PASS] OAEP: dog_torch encrypt -> OpenSSL decrypt" << std::endl;
					else
					{
						std::cout << "[FAIL] OAEP: dog_torch encrypt -> OpenSSL decrypt mismatch" << std::endl;
						error++;
					}
				}
			}
			else
			{
				print_openssl_error("EVP_PKEY_decrypt_init failed");
				error++;
			}
			EVP_PKEY_CTX_free(ctx);
		}

		// 4b. OpenSSL encrypt -> dog_torch decrypt
		{
			EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(evp_pub, NULL);
			bool ok = ctx && EVP_PKEY_encrypt_init(ctx) > 0;
			if (ok)
			{
				EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
				EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
				EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
				EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, NULL, 0);

				std::vector<unsigned char> ct(k);
				size_t ctlen = ct.size();
				if (EVP_PKEY_encrypt(ctx, ct.data(), &ctlen,
						reinterpret_cast<const unsigned char*>(plain.data_ptr()),
						plain.size()) <= 0)
				{
					print_openssl_error("EVP_PKEY_encrypt(OAEP) failed");
					error++;
				}
				else
				{
					BinaryData ct_bd(std::vector<uint8_t>(ct.begin(), ct.begin() + ctlen));
					BinaryData decrypted = DTRSA::decrypt(ct_bd, key_pair.private_key, key_size);
					// re-attach the leading 0x00 (and any stripped seed bytes) before unpadding
					BinaryData padded = left_pad_to(decrypted, k - 1);
					BinaryData recovered = oaep.get_unpadding()(padded);
					if (recovered == plain)
						std::cout << "[PASS] OAEP: OpenSSL encrypt -> dog_torch decrypt" << std::endl;
					else
					{
						std::cout << "[FAIL] OAEP: OpenSSL encrypt -> dog_torch decrypt mismatch" << std::endl;
						error++;
					}
				}
			}
			else
			{
				print_openssl_error("EVP_PKEY_encrypt_init failed");
				error++;
			}
			EVP_PKEY_CTX_free(ctx);
		}

		// 4c. dog_torch full OAEP round-trip (sanity check)
		std::cout << "\n--- dog_torch OAEP round-trip ---" << std::endl;
		{
			BinaryData p = plain;
			p = oaep.get_padding()(p);
			BinaryData c = DTRSA::encrypt(p, key_pair.public_key, key_size);
			c = DTRSA::decrypt(c, key_pair.private_key, key_size);
			c = left_pad_to(c, k - 1);
			p = oaep.get_unpadding()(c);
			if (p == plain)
				std::cout << "[PASS] dog_torch OAEP encrypt/decrypt round-trip" << std::endl;
			else
			{
				std::cout << "[FAIL] dog_torch OAEP round-trip" << std::endl;
				error++;
			}
		}
	}

	// ------------------------------------------------------------------
	// cleanup
	// ------------------------------------------------------------------
	EVP_PKEY_free(evp_pub);
	EVP_PKEY_free(evp_priv);

	std::cout << "\n# case errors: " << error << std::endl;
	return error;
}

int main()
{
	std::cout << "=== RSA test: dog_torch vs OpenSSL "
			  << OPENSSL_VERSION_TEXT << " ===" << std::endl;

	// test combinations: multiple key sizes x multiple public exponents.
	// 512 is omitted because OAEP-SHA256 needs k >= 2*hlen+2 = 66 bytes.
	const std::vector<uint64_t> key_sizes = { 512, 1024, 2048, 3072, 4096 };
	const std::vector<uint32_t> pub_exps = { 3, 17, 65537 };

	uint64_t total_error = 0;
	uint64_t case_count = 0;
	for (uint64_t ks : key_sizes)
	{
		for (uint32_t e : pub_exps)
		{
			total_error += run_rsa_case(ks, e);
			case_count++;
		}
	}

	std::cout << "\n=== SUMMARY: " << case_count << " cases, total errors: "
			  << total_error << " ===" << std::endl;
	return (int)total_error;
}
