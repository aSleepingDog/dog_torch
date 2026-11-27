#include "crypto/sym/block/algorithms/SM4.h"

using dog_torch::serialize::BinaryData;
using dog_torch::crypto::sym::block::algorithm::SM4;
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

    std::cout << "test set from " << R"<url>(GM/T0002-2012)<url>" << std::endl;

    {
        BinaryData k = { "0123456789ABCDEFFEDCBA9876543210",BinaryData::Type::Hex};
        BinaryData p0 = { "0123456789ABCDEFFEDCBA9876543210",BinaryData::Type::Hex };
        auto alg = SM4();
        auto ke = alg.get_extend_key()(k, alg.get_block_size(), alg.get_key_size());
        auto c0 = alg.get_encrypt()(p0, alg.get_block_size(), ke, alg.get_key_size());
        BinaryData c0_r = { "681EDF34D206965E86B3E94F536E4246",BinaryData::Type::Hex};
        auto p1 = alg.get_decrypt()(c0, alg.get_block_size(), ke, alg.get_key_size());
        output0(count, p0, alg.fmt_string(), k, c0, c0_r, p1);
        if (c0 != c0_r) c_error++;
        if (p0 != p1) p_error++;
    };

    {
        BinaryData k = { "0123456789ABCDEFFEDCBA9876543210",BinaryData::Type::Hex };
        BinaryData p0 = { "0123456789ABCDEFFEDCBA9876543210",BinaryData::Type::Hex };
        auto alg = SM4();
        auto ke = alg.get_extend_key()(k, alg.get_block_size(), alg.get_key_size());
        auto c0 = p0;
        for (uint64_t i = 0; i < 1000000; ++i)
        {
            c0 = alg.get_encrypt()(c0, alg.get_block_size(), ke, alg.get_key_size());
        }
        BinaryData c0_r = { "595298C7C6FD271F0402F804C33D3F66",BinaryData::Type::Hex };
        auto p1 = c0;
        for (uint64_t i = 0; i < 1000000; ++i)
        {
            p1 = alg.get_decrypt()(p1, alg.get_block_size(), ke, alg.get_key_size());
        }
        output0(count, p0, alg.fmt_string(), k, c0, c0_r, p1);
        if (c0 != c0_r) c_error++;
        if (p0 != p1) p_error++;
    };
    std::cout << "error " << c_error << " / " << p_error << std::endl;

}