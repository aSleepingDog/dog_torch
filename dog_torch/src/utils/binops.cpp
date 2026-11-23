#include "utils/binops.h"

namespace NSROOT = dog_torch::utils;

std::string NSROOT::to_utf8(uint64_t code)
{
    std::string result = "";
    if (code <= 0x7F)
    {
        result += (char)code;
    }
    else if (code <= 0x7FF)
    {
        result += (char)(0b11000000 | ((code >> 06) & 0x1F));
        result += (char)(0b10000000 | ((code >> 00) & 0x3F));
    }
    else if (code <= 0xFFFF)
    {
        result += (char)(0b11100000 | ((code >> 12) & 0x0F));
        result += (char)(0b10000000 | ((code >> 06) & 0x3F));
        result += (char)(0b10000000 | ((code >> 00) & 0x3F));
    }
    else if (code <= 0x1FFFFF)
    {
        result += (char)(0b11110000 | ((code >> 18) & 0x07));
        result += (char)(0b10000000 | ((code >> 12) & 0x3F));
        result += (char)(0b10000000 | ((code >> 06) & 0x3F));
        result += (char)(0b10000000 | ((code >> 00) & 0x3F));
    }
    else if (code <= 0x3FFFFFF)
    {
        result += (char)(0b11111000 | ((code >> 24) & 0x03));
        result += (char)(0b10000000 | ((code >> 18) & 0x3F));
        result += (char)(0b10000000 | ((code >> 12) & 0x3F));
        result += (char)(0b10000000 | ((code >> 06) & 0x3F));
        result += (char)(0b10000000 | ((code >> 00) & 0x3F));
    }
    else if (code <= 0x7FFFFFFF)
    {
        result += (char)(0b11111100 | ((code >> 30) & 0x01));
        result += (char)(0b10000000 | ((code >> 24) & 0x3F));
        result += (char)(0b10000000 | ((code >> 18) & 0x3F));
        result += (char)(0b10000000 | ((code >> 12) & 0x3F));
        result += (char)(0b10000000 | ((code >> 06) & 0x3F));
        result += (char)(0b10000000 | ((code >> 00) & 0x3F));
    }
    else if (code <= 0xFFFFFFFF)
    {
        result += (char)(0b11111100 | ((code >> 36) & 0x01));
        result += (char)(0b10000000 | ((code >> 30) & 0x3F));
        result += (char)(0b10000000 | ((code >> 24) & 0x3F));
        result += (char)(0b10000000 | ((code >> 18) & 0x3F));
        result += (char)(0b10000000 | ((code >> 12) & 0x3F));
        result += (char)(0b10000000 | ((code >> 06) & 0x3F));
        result += (char)(0b10000000 | ((code >> 00) & 0x3F));
    }
    return result;
}
std::string to_string(std::u8string_view u8str)
{
    std::string result;
    for (auto c : u8str)
    {
        result += static_cast<char>(c);
    }
    return result;
}

std::vector<uint8_t> NSROOT::sub_bytes_pos(const std::vector<uint8_t>& input, uint64_t start, uint64_t end)
{
    return std::vector<uint8_t>(input.cbegin() + start, end >= input.size() ? input.cend() : input.cbegin() + end);
}
std::vector<uint8_t> NSROOT::sub_bytes_len(const std::vector<uint8_t>& input, uint64_t start, uint64_t length)
{
    return std::vector<uint8_t>(
        input.cbegin() + start,
        start + length >= input.size() ? input.cend() : input.cbegin() + start + length);
}

std::vector<uint8_t> NSROOT::bit_move(const std::vector<uint8_t>& input, bool is_right, bool allow_resize, uint64_t shift)
{
    if (shift == 0) return input;
    uint64_t byte_shift = shift / 8;
    if (!allow_resize && byte_shift >= input.size())
    {
        return std::vector<uint8_t>();
    }
    uint64_t bit_shift = shift % 8;
    uint8_t temp = 0, buf = 0;
    std::vector<uint8_t> result;
    if (is_right)
    {
        if (allow_resize)
        {
            result.resize(byte_shift + input.size());
            std::copy(input.cbegin(), input.cend(), result.begin() + byte_shift);
            for (auto it = result.begin() + byte_shift; it != result.end(); ++it)
            {
                temp = *it;
                *it = (temp >> bit_shift) | buf;
                buf = temp << (8 - bit_shift);
            }
            if (buf)
            {
                result.push_back(buf);
            }
        }
        else
        {
            result.resize(input.size() - byte_shift);
            std::copy(input.cbegin(), input.cend() - byte_shift, result.begin());
            for (auto it = result.begin(); it != result.end(); ++it)
            {
                temp = *it;
                *it = (temp >> bit_shift) | buf;
                buf = temp << (8 - bit_shift);
            }
        }
    }
    else
    {
        if (allow_resize)
        {
            result.resize(byte_shift + input.size());
            std::copy(input.cbegin(), input.cend(), result.begin());
            for (auto it = result.rbegin() + byte_shift; it != result.rend(); ++it)
            {
                temp = *it;
                *it = (temp << bit_shift) | buf;
                buf = temp >> (8 - bit_shift);
            }
            if (buf)
            {
                result.insert(result.cbegin(), buf);
            }
        }
        else
        {
            result.resize(input.size() - byte_shift);
            std::copy(input.cbegin() + byte_shift, input.cend(), result.begin());
            for (auto it = result.rbegin(); it != result.rend(); ++it)
            {
                temp = *it;
                *it = (temp << bit_shift) | buf;
                buf = temp >> (8 - bit_shift);
            }
        }
    }
    return result;
}
void NSROOT::bit_move_self(std::vector<uint8_t>& input, bool is_right, bool allow_resize, uint64_t shift)
{
    if (shift == 0) return;
    uint64_t byte_shift = shift / 8;
    if (!allow_resize && byte_shift >= input.size())
    {
        input.clear();
        return;
    }
    uint64_t bit_shift = shift % 8;
    uint8_t temp = 0, buf = 0;
    if (is_right)
    {
        if (allow_resize)
        {
            input.insert(input.begin(), byte_shift, 0);
            for (auto it = input.begin() + byte_shift; it != input.end(); ++it)
            {
                temp = *it;
                *it = (temp >> bit_shift) | buf;
                buf = temp << (8 - bit_shift);
            }
            if (buf)
            {
                input.push_back(buf);
            }
        }
        else
        {
            std::move(input.cbegin(), input.cend() - byte_shift, input.begin() + byte_shift);
            std::fill(input.begin(), input.begin() + byte_shift, 0);
            for (auto it = input.begin() + byte_shift; it != input.end(); ++it)
            {
                temp = *it;
                *it = (temp >> bit_shift) | buf;
                buf = temp << (8 - bit_shift);
            }

        }
    }
    else
    {
        if (allow_resize)
        {
            for (uint64_t i = 0; i < byte_shift; ++i) input.push_back(0);
            for (auto it = input.rbegin() + byte_shift; it != input.rend(); ++it)
            {
                temp = *it;
                *it = (temp << bit_shift) | buf;
                buf = temp >> (8 - bit_shift);
            }
            if (buf)
            {
                input.insert(input.cbegin(), buf);
            }
        }
        else
        {
            std::copy(input.begin() + byte_shift, input.end(), input.begin());
            std::fill(input.rbegin(), input.rbegin() + byte_shift, 0);
            for (auto it = input.rbegin() + byte_shift; it != input.rend(); ++it)
            {
                temp = *it;
                *it = (temp << bit_shift) | buf;
                buf = temp >> (8 - bit_shift);
            }
        }
    }
}

std::vector<uint8_t> NSROOT::sub_bits_pos(const std::vector<uint8_t>& input, uint64_t byte_start, uint8_t bit_start, uint64_t byte_end, uint8_t bit_end)
{
    if (bit_end > 0) byte_end++;
    std::vector<uint8_t> result = sub_bytes_pos(input, byte_start, byte_end);
    if (!result.size()) return result;
    uint8_t mask = bit_end > 0 ? 0xff << (8 - bit_end) : 0xff;
    result.back() &= mask;
    return bit_move(result, false, false, bit_start);
}
std::vector<uint8_t> NSROOT::sub_bits_len(const std::vector<uint8_t>& input, uint64_t byte_start, uint8_t bit_start, uint64_t length)
{
    uint64_t byte_end =
        byte_start + ((bit_start + length) / 8) < input.size() ?
        byte_start + ((bit_start + length) / 8) : input.size();
    uint8_t bit_end =
        byte_start + ((bit_start + length) / 8) < input.size() ?
        (bit_start + length) % 8 : 0;
    return sub_bits_pos(input, byte_start, bit_start, byte_end, bit_end);
}