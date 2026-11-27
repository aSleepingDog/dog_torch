//#include "crypto/asym/algorithms/RSA.h"
//#include "crypto/asym/paddings/OAEP.h"
//
//#include "crypto/hash/hash_algorithms.h"
//
//int main()
//{
//	using dog_torch::serialize::BinaryData;
//	using dog_torch::crypto::asym::Cipher;
//	using dog_torch::crypto::asym::KeyPair;
//	using dog_torch::crypto::asym::algorithm::RSA;
//	using dog_torch::crypto::asym::padding::OAEP;
//
//	uint64_t key_size = 2048;
//
//	RSA alg = RSA(key_size, 65537);
//
//	using dog_torch::crypto::hash::algorithm::SHA2;
//
//	OAEP padding = OAEP(SHA2(256), key_size, BinaryData("", BinaryData::Type::UTF8));
//
//	BinaryData plain{ "Hello world!",BinaryData::Type::UTF8 };
//
//	Cipher cipher(alg, padding);
//	cipher.init();
//	cipher.init_key();
//	auto crypt = cipher.encrypt(plain);
//	plain = cipher.decrypt(crypt);
//
//	std::cout << plain.to_string() << std::endl;
//}

//#include <iostream>
//#include <chrono>
//#include <thread>
//#include <cstdint>
//#include "crypto/hash/hash_algorithms.h"
//
//int main()
//{
//	using dog_torch::crypto::hash::Generator;
//	using dog_torch::crypto::hash::algorithm::SHA2;
//
//	auto gen = Generator(SHA2(256));
//	std::cout << gen.fmt_string() << std::endl;
//}
#include <wmmintrin.h>

#include "serialize/BinaryData.h"

using dog_torch::serialize::BinaryData;

const uint8_t SBox[16][16] = {
    //0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },//0
    { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },//1
    { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },//2
    { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },//3
    { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },//4
    { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },//5
    { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },//6
    { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },//7
    { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },//8
    { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },//9
    { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },//A
    { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },//B
    { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },//C
    { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },//D
    { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },//E
    { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 } };//F
const uint8_t Round[16] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };//todo 使用循环元0x011b填充后续元素……

BinaryData extend_key(const BinaryData& key, uint64_t block_size, uint64_t key_size)
{
    if (key_size != 128 && key_size != 192 && key_size != 256)
    {
        throw 1;
    }
    else if (key_size == 128)
    {
        BinaryData res;
        res.reserve(176);
        if (key.size() < 16)
        {
            throw 1;
        }
        for (int i = 0; i < 16; i++)
        {
            res.push_back(key.at(i));
        }
        for (int i = 16; i < 176; i += 4)
        {
            if (i % 16 == 0)
            {
                //取当前列-1
                uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
                //列位移
                uint8_t typeB = temp1[0];
                for (int i = 0; i < 3; i++)
                {
                    temp1[i] = temp1[i + 1];
                }
                temp1[3] = typeB;
                //字节代还
                for (int i = 0; i < 4; i++)
                {
                    temp1[i] = SBox[temp1[i] >> 4][temp1[i] & 0x0f];
                }
                //轮常量异或
                temp1[0] = temp1[0] ^ Round[(i / 16) - 1];
                //取当前列-4并异或
                uint8_t temp2[4] = { res.at(i - 16), res.at(i - 15), res.at(i - 14), res.at(i - 13) };
                for (int i = 0; i < 4; i++)
                {
                    res.push_back(temp1[i] ^ temp2[i]);
                }
            }
            else
            {
                //取当前列-1
                uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
                //取当前列-4并异或
                uint8_t temp2[4] = { res.at(i - 16), res.at(i - 15), res.at(i - 14), res.at(i - 13) };
                for (int i = 0; i < 4; i++)
                {
                    res.push_back(temp1[i] ^ temp2[i]);
                }
            }
        }
        return res;
    }
    else if (key_size == 192)
    {
        BinaryData res;
        res.reserve(208);
        if (key.size() < 24)
        {
            throw 1;
        }
        for (int i = 0; i < 24; i++)
        {
            res.push_back(key.at(i));
        }
        for (int i = 24; i < 208; i += 4)
        {
            if (i % 24 == 0)
            {
                //取当前列-1
                uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
                //列位移
                uint8_t typeB = temp1[0];
                for (int i = 0; i < 3; i++)
                {
                    temp1[i] = temp1[i + 1];
                }
                temp1[3] = typeB;
                //字节代还
                for (int i = 0; i < 4; i++)
                {
                    temp1[i] = SBox[temp1[i] >> 4][temp1[i] & 0x0f];
                }
                //轮常量异或
                temp1[0] = temp1[0] ^ Round[(i / 24) - 1];
                //取当前列-6并异或
                uint8_t temp2[4] = { res.at(i - 24), res.at(i - 23), res.at(i - 22), res.at(i - 21) };
                for (int i = 0; i < 4; i++)
                {
                    res.push_back(temp1[i] ^ temp2[i]);
                }
            }
            else
            {
                //取当前列-1
                uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
                //取当前列-6并异或
                uint8_t temp2[4] = { res.at(i - 24), res.at(i - 23), res.at(i - 22), res.at(i - 21) };
                for (int i = 0; i < 4; i++)
                {
                    res.push_back(temp1[i] ^ temp2[i]);
                }
            }
        }
        return res;
    }
    else if (key_size == 256)
    {
        BinaryData res;
        res.reserve(240);
        if (key.size() < 32)
        {
            throw 1;
        }
        for (int i = 0; i < 32; i++)
        {
            res.push_back(key.at(i));
        }
        for (int i = 32; i < 240; i += 4)
        {
            if (i % 32 == 0)
            {
                //取当前列-1
                uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
                //列位移
                uint8_t typeB = temp1[0];
                for (int i0 = 0; i0 < 3; i0++)
                {
                    temp1[i0] = temp1[i0 + 1];
                }
                temp1[3] = typeB;
                //字节代还
                for (int i0 = 0; i0 < 4; i0++)
                {
                    temp1[i0] = SBox[temp1[i0] >> 4][temp1[i0] & 0x0f];
                }
                //轮常量异或
                temp1[0] = temp1[0] ^ Round[(i / 32) - 1];
                //取当前列-8并异或
                uint8_t temp2[4] = { res.at(i - 32), res.at(i - 31), res.at(i - 30), res.at(i - 29) };
                for (int i0 = 0; i0 < 4; i0++)
                {
                    res.push_back(temp1[i0] ^ temp2[i0]);
                }
            }
            else if (i % 16 == 0)
            {
                //取当前列-1
                uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
                for (int i0 = 0; i0 < 4; i0++)
                {
                    temp1[i0] = SBox[temp1[i0] >> 4][temp1[i0] & 0x0f];
                }
                //取当前列-8并异或
                uint8_t temp2[4] = { res.at(i - 32), res.at(i - 31), res.at(i - 30), res.at(i - 29) };
                for (int i0 = 0; i0 < 4; i0++)
                {
                    res.push_back(temp1[i0] ^ temp2[i0]);
                }
            }
            else
            {
                //取当前列-1
                uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
                //取当前列-8并异或
                uint8_t temp2[4] = { res.at(i - 32), res.at(i - 31), res.at(i - 30), res.at(i - 29) };
                for (int i0 = 0; i0 < 4; i0++)
                {
                    res.push_back(temp1[i0] ^ temp2[i0]);
                }
            }
        }
        return res;
    }
    return BinaryData();
}


void showing(__m128i* block)
{
    uint8_t* p = reinterpret_cast<uint8_t*>(block);
    for (uint32_t i = 0; i < 16; i++)
    {
        std::cout << std::format("{:02x}", static_cast<uint8_t>(p[i]));
    }
    std::cout << std::endl;
}

BinaryData x64_encoding(const BinaryData& plain, uint64_t block_size, const BinaryData& key, uint64_t key_size)
{
    std::array<uint8_t, 16> mid_block{ 0 };
    std::copy(plain.cbegin(), plain.cend(), mid_block.begin());
    __m128i* tmp = (__m128i*) (&mid_block[0]);
    __m128i* keyp = (__m128i*) (&key[0]);
    showing(tmp);
    showing(keyp);
    std::cout << std::endl;
    *tmp = _mm_xor_si128(*tmp, keyp[0]);
    showing(tmp);
    showing(keyp);
    std::cout << std::endl;
    uint32_t i = 0;
    for (; i < ((key_size / 32) + 5); i++)
    {
        *tmp = _mm_aesenc_si128(*tmp, keyp[i + 1]);
        showing(tmp);
        showing(keyp + (i + 1));
        std::cout << std::endl;
    }
    *tmp = _mm_aesenclast_si128(*tmp, keyp[i + 1]);
    showing(tmp);
    showing(keyp + (i + 1));
    std::cout << std::endl;
    return mid_block;
}


int main()
{
    BinaryData key("80000000000000000000000000000000", BinaryData::Type::Hex);
    BinaryData plain("00000000000000000000000000000000", BinaryData::Type::Hex);

    key = extend_key(key, 128, 128);

    x64_encoding(plain, 128, key, 128);
}