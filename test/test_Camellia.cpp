#include "crypto/sym/block/algorithms/Camellia.h"

using dog_torch::serialize::BinaryData;
using dog_torch::crypto::sym::block::algorithm::Camellia;
using dog_torch::crypto::sym::block::BlockCipher;

void output0(uint64_t count, const BinaryData& p0, const std::string& ci, const BinaryData& k, const BinaryData& c0, const BinaryData& c0_r, const BinaryData& p1)
{
    std::cout << "[id]" << std::endl;
    std::cout << count << std::endl;
    std::cout << "[plain]" << std::endl;
    std::cout << p0.to_hex_string(false) << ":Hex:lower" << std::endl;
    std::cout << "[operator]" << std::endl;
    std::cout << ci << std::endl;
    std::cout << k.to_hex_string(false) << ":Hex:lower" << std::endl;
    std::cout << "[crypt]" << std::endl;
    std::cout << c0.to_hex_string(false) << ":Hex:lower" << std::endl;
    std::cout << c0_r.to_hex_string(false) << ":Hex:lower" << std::endl;
    std::cout << std::boolalpha << (c0 == c0_r) << std::endl;
    std::cout << "[plain]" << std::endl;
    std::cout << p1.to_hex_string(false) << ":Hex:lower" << std::endl;
    std::cout << std::boolalpha << (p0 == p1) << std::endl;
    std::cout << std::endl;
}

int main()
{
    uint64_t count = 0;
    uint64_t c_error = 0;
    uint64_t p_error = 0;

    std::cout << "test set from " << R"<url>(https://info.isl.ntt.co.jp/crypt/eng/camellia/dl/01espec.pdf)<url>" << std::endl;

    {
        BinaryData k = { "0123456789ABCDEFFEDCBA9876543210",BinaryData::Type::Hex };
        BinaryData p0 = { "0123456789ABCDEFFEDCBA9876543210",BinaryData::Type::Hex };
        auto alg = Camellia(128);
        auto ke = alg.get_extend_key()(k, alg.get_block_size(), alg.get_key_size());
        auto c0 = alg.get_encrypt()(p0, alg.get_block_size(), ke, alg.get_key_size());
        BinaryData c0_r = { "67673138549669730857065648eabe43",BinaryData::Type::Hex };
        auto p1 = alg.get_decrypt()(c0, alg.get_block_size(), ke, alg.get_key_size());
        output0(count, p0, alg.fmt_string(), k, c0, c0_r, p1);
        if (c0 != c0_r) c_error++;
        if (p0 != p1) p_error++;
    };

    {
        BinaryData k = { "0123456789ABCDEFFEDCBA98765432100011223344556677",BinaryData::Type::Hex };
        BinaryData p0 = { "0123456789ABCDEFFEDCBA9876543210",BinaryData::Type::Hex };
        auto alg = Camellia(192);
        auto ke = alg.get_extend_key()(k, alg.get_block_size(), alg.get_key_size());
        auto c0 = alg.get_encrypt()(p0, alg.get_block_size(), ke, alg.get_key_size());
        BinaryData c0_r = { "b4993401b3e996f84ee5cee7d79b09b9",BinaryData::Type::Hex };
        auto p1 = alg.get_decrypt()(c0, alg.get_block_size(), ke, alg.get_key_size());
        output0(count, p0, alg.fmt_string(), k, c0, c0_r, p1);
        if (c0 != c0_r) c_error++;
        if (p0 != p1) p_error++;
    };

    {
        BinaryData k = { "0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF",BinaryData::Type::Hex };
        BinaryData p0 = { "0123456789ABCDEFFEDCBA9876543210",BinaryData::Type::Hex };
        auto alg = Camellia(256);
        auto ke = alg.get_extend_key()(k, alg.get_block_size(), alg.get_key_size());
        auto c0 = alg.get_encrypt()(p0, alg.get_block_size(), ke, alg.get_key_size());
        BinaryData c0_r = { "9acc237dff16d76c20ef7c919e3a7509",BinaryData::Type::Hex };
        auto p1 = alg.get_decrypt()(c0, alg.get_block_size(), ke, alg.get_key_size());
        output0(count, p0, alg.fmt_string(), k, c0, c0_r, p1);
        if (c0 != c0_r) c_error++;
        if (p0 != p1) p_error++;
    };

    std::cout << "error " << c_error << " / " << p_error << std::endl;

}