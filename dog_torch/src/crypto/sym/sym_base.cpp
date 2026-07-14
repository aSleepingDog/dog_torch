#include "crypto/sym/sym_base.h"

namespace NSROOT = dog_torch::crypto::sym;
using BinaryData = dog_torch::serialize::BinaryData;
using Value = dog_torch::serialize::tlv::Value;

NSROOT::Cipher::Cipher() = default;
NSROOT::Cipher::Cipher(const BinaryData & key) : ori_key_(key) {}
NSROOT::Cipher::~Cipher() = default;

std::unique_ptr<NSROOT::Cipher> NSROOT::Cipher::clone() const
{
    return std::make_unique<Cipher>(*this);
}
void NSROOT::Cipher::init()
{}

bool NSROOT::Cipher::effective() const
{
    return this->is_effective_;
}

void NSROOT::Cipher::set_key(const BinaryData& key)
{
    this->ori_key_ = key;
}
BinaryData NSROOT::Cipher::key() const
{
    return this->ori_key_;
}
std::string NSROOT::Cipher::fmt_string() const
{
    return "";
}
Value NSROOT::Cipher::serialize() const
{
    return nullptr;
}
BinaryData NSROOT::Cipher::encrypt(const BinaryData& plain)
{
    return BinaryData();
}
BinaryData NSROOT::Cipher::decrypt(const BinaryData& crypt)
{
    return BinaryData();
}

void NSROOT::Cipher::encrypt_stream(std::istream& plain, uint64_t total, std::ostream& crypt)
{}
void NSROOT::Cipher::decrypt_stream(std::istream & crypt, uint64_t total, std::ostream & plain)
{}

void NSROOT::Cipher::encryptp_stream(PauseableChannel & pc, std::istream & plain, uint64_t total, std::ostream & crypt)
{}
void NSROOT::Cipher::decryptp_stream(PauseableChannel & pc, std::istream & crypt, uint64_t total, std::ostream & plain)
{}

#define NAMESPACE(name) dog_torch__crypto__sym__##name
#define CRYPTO_BASE(name) dog_torch__crypto__##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

void                       NAMESPACE(Cipher_init)                (LVALUE(UTILS(CppResultSet)) result_set, LVALUE(NAMESPACE(Cipher)) self)
{
    try
    {
        self->init();
    }
    catch (const std::exception& e)
    {
        dog_torch::utils::CppResultSet_reset(result_set, -1, e.what());
    }
}
uint8_t                    NAMESPACE(Cipher_effective)           (const LVALUE(NAMESPACE(Cipher)) self)
{
    return self->effective();
}
SERIALIZE(BinaryData)* NAMESPACE(Cipher_key)                 (const LVALUE(NAMESPACE(Cipher)) self)
{
    return new SERIALIZE(BinaryData)(self->key());
}
void                       NAMESPACE(Cipher_set_key)             (LVALUE(NAMESPACE(Cipher)) self, const LVALUE(SERIALIZE(BinaryData)) key)
{
    if (key == nullptr) return;
    self->set_key(*key);
}

SERIALIZE(BinaryData)* NAMESPACE(Cipher_encrypt)             (LVALUE(UTILS(CppResultSet)) result_set, LVALUE(NAMESPACE(Cipher)) self, const LVALUE(SERIALIZE(BinaryData)) plain)
{
    if (self == nullptr)
    {
        dog_torch::utils::CppResultSet_reset(result_set, -1, "self is null");
        return nullptr;
    }
    try
    {
        return new SERIALIZE(BinaryData){ self->encrypt(*plain) };
    }
    catch (const std::exception& e)
    {
        dog_torch::utils::CppResultSet_reset(result_set, -1, e.what());
        return nullptr;
    }
}
SERIALIZE(BinaryData)* NAMESPACE(Cipher_decrypt)             (LVALUE(UTILS(CppResultSet)) result_set, LVALUE(NAMESPACE(Cipher)) self, const LVALUE(SERIALIZE(BinaryData)) crypt)
{
    if (self == nullptr)
    {
        dog_torch::utils::CppResultSet_reset(result_set, -1, "self is null");
        return nullptr;
    }
    try
    {
        return new SERIALIZE(BinaryData){ self->encrypt(*crypt) };
    }
    catch (const std::exception& e)
    {
        dog_torch::utils::CppResultSet_reset(result_set, -1, e.what());
        return nullptr;
    }
}

void     NAMESPACE(Cipher_encrypt_stream)      (LVALUE(UTILS(CppResultSet)) result_set, LVALUE(NAMESPACE(Cipher)) self, const LVALUE(UTILS(CppString)) plain, uint64_t total, const LVALUE(UTILS(CppString)) crypt)
{
    if (self == nullptr)
    {
        dog_torch::utils::CppResultSet_reset(result_set, -1, "self is null");
        return;
    }
    if (plain == nullptr)
    {
        dog_torch::utils::CppResultSet_reset(result_set, -2, "plain is null");
        return;
    }
    std::string plain_path = dog_torch::utils::to_string(plain);
    if (!std::filesystem::exists(plain_path))
    {
        dog_torch::utils::CppResultSet_reset(result_set, -3, "plain file not exists");
        return;
    }
    uint64_t input_file_size = std::filesystem::file_size(plain_path);
    std::ifstream plain_file(plain_path, std::ios::binary);
    if (crypt == nullptr)
    {
        dog_torch::utils::CppResultSet_reset(result_set, -4, "crypt is null");
        return;
    }
    std::string crypt_path = dog_torch::utils::to_string(crypt);
    std::ofstream crypt_file(crypt_path, std::ios::binary);
    if (!crypt_file.is_open())
    {
        dog_torch::utils::CppResultSet_reset(result_set, -5, "output file open failed. maybe permission denied or not access");
        return;
    }
    try
    {
        self->encrypt_stream(plain_file, input_file_size, crypt_file);
    }
    catch (const std::exception& e)
    {
        dog_torch::utils::CppResultSet_reset(result_set, -6, e.what());
    }
}
void     NAMESPACE(Cipher_decrypt_stream)      (LVALUE(UTILS(CppResultSet)) result_set, LVALUE(NAMESPACE(Cipher)) self, const LVALUE(UTILS(CppString)) crypt, uint64_t total, const LVALUE(UTILS(CppString)) plain)
{
    if (self == nullptr)
    {
        dog_torch::utils::CppResultSet_reset(result_set, -1, "self is null");
        return;
    }

    if (crypt == nullptr)
    {
        dog_torch::utils::CppResultSet_reset(result_set, -2, "crypt is null");
        return;
    }
    std::string crypt_path = dog_torch::utils::to_string(crypt);
    if (!std::filesystem::exists(crypt_path))
    {
        dog_torch::utils::CppResultSet_reset(result_set, -3, "crypt file not exists");
        return;
    }
    uint64_t input_file_size = std::filesystem::file_size(crypt_path);
    std::ifstream crypt_file(crypt_path, std::ios::binary);
    
    if (plain == nullptr)
    {
        dog_torch::utils::CppResultSet_reset(result_set, -4, "plain is null");
        return;
    }
    std::string plain_path = dog_torch::utils::to_string(plain);
    std::ofstream plain_file(crypt_path, std::ios::binary);
    if (!plain_file.is_open())
    {
        dog_torch::utils::CppResultSet_reset(result_set, -5, "output file open failed. maybe permission denied or not access");
        return;
    }
    try
    {
        self->decrypt_stream(crypt_file, input_file_size, plain_file);
    }
    catch (const std::exception& e)
    {
        dog_torch::utils::CppResultSet_reset(result_set, -6, e.what());
    }
}


#undef NAMESPACE
#undef CRYPTO_BASE
#undef SERIALIZE
#undef UTILS