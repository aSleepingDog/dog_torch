#include "math/number.h"

namespace NSROOT = dog_torch::math::number;
using dog_torch::utils::from_c_str;
using dog_torch::utils::operator+;
using dog_torch::utils::from_uint64;
using dog_torch::utils::array_to_view;

constexpr auto ERROR_DIVIDE_BY_ZERO = from_c_str("division by zero");
constexpr auto ERROR_UNEXPECT_RADIX = from_c_str("unsupported radix");

constexpr auto ERROR_RADIX_UNEXPECT_CHAR_2 = (from_c_str("unexcept char when ") + from_uint64<2>());
constexpr auto ERROR_RADIX_UNEXPECT_CHAR_8 = (from_c_str("unexcept char when ") + from_uint64<8>());
constexpr auto ERROR_RADIX_UNEXPECT_CHAR_10 = (from_c_str("unexcept char when ") + from_uint64<10>());
constexpr auto ERROR_RADIX_UNEXPECT_CHAR_16 = (from_c_str("unexcept char when ") + from_uint64<16>());

constexpr auto ERROR_UNSIGNED_SUBTRACT_LESS = "a<b when unsigned numbers subtract";

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
void u64add(uint64_t carry_in, uint64_t a, uint64_t b, uint64_t* carry, uint64_t* result)
{
    *carry = _addcarry_u64(static_cast<unsigned char>(carry_in), a, b, result);
}
void u64sub(uint64_t borrow_in, uint64_t a, uint64_t b, uint64_t* borrow, uint64_t* result)
{
    *borrow = _subborrow_u64(static_cast<unsigned char>(borrow_in), a, b, result);
}
#if defined(_MSC_VER)
void u64mul(uint64_t a, uint64_t b, uint64_t* result_high, uint64_t* result_low)
{
    *result_low = _umul128(a, b, result_high);
}
void u128div(uint64_t a_h, uint64_t a_l, uint64_t b, uint64_t* q, uint64_t* r)
{
    *q = _udiv128(a_h, a_l, b, r);
}
#elif defined(__GNUC__)
void u64mul(uint64_t a, uint64_t b, uint64_t* result_high, uint64_t* result_low)
{
    unsigned __int128 c = (unsigned __int128)a * (unsigned __int128)b;
    *result_high = (uint64_t)(c >> 64);
    *result_low = (uint64_t)c;
}
void u128div(uint64_t a_h, uint64_t a_l, uint64_t b, uint64_t* q, uint64_t* r)
{
    unsigned __int128 dividend = ((unsigned __int128)a_h << 64) | (unsigned __int128)a_l;
    unsigned __int128 quotient = dividend / (unsigned __int128)b;
    unsigned __int128 remainder = dividend % (unsigned __int128)b;
    *q = (uint64_t)quotient;
    *r = (uint64_t)remainder;
}
#endif
// #elif defined(__aarch64__) || defined(_M_ARM64)
#else
//纯软件模拟
void u64add(uint64_t carry_in, uint64_t a, uint64_t b, uint64_t* carry, uint64_t* result)
{
    uint64_t low = (a & 0xFFFFFFFF) + (b & 0xFFFFFFFF) + carry_in;
    uint64_t high = (a >> 32) + (b >> 32) + (low >> 32);
    *carry = high >> 32;
    *result = high << 32 | low;
}
void u64sub(uint64_t borrow_in, uint64_t a, uint64_t b, uint64_t* borrow, uint64_t* result)
{
    uint64_t carry = b == 0xFFFFFFFFFFFFFFFF && borrow_in == 1 ? 1 : 0;
    b += borrow_in;
    //carry|b = b + borrow_in
    bool com = a >= b;
    *borrow = carry | !com;
    *result = com ? a - b : (~(b - a) + 1);
}
void u64mul(uint64_t a, uint64_t b, uint64_t* result_high, uint64_t* result_low)
{
    uint32_t a0 = a & 0xffffffff;
    uint32_t a1 = a >> 32;
    uint32_t b0 = b & 0xffffffff;
    uint32_t b1 = b >> 32;

    uint64_t low = (uint64_t)a0 * b0;
    uint64_t high = (uint64_t)a1 * b1;
    uint64_t mid0 = (uint64_t)a0 * b1;
    uint64_t mid1 = (uint64_t)a1 * b0;
    if (mid0 > 0xffffffffffffffff - mid1)
    {
        high += 0x100000000;
    }
    mid0 += mid1;
    high += (mid0) >> 32;
    if (low > 0xffffffffffffffff - (mid0 << 32))
    {
        high++;
    }
    low += mid0 << 32;

    *result_high = high;
    *result_low = low;
}
void u128div(uint64_t a_h, uint64_t a_l, uint64_t b, uint64_t* q, uint64_t* r)
{
    for (uint64_t i = 0; i < 64; ++i)
    {
        a_h = a_h << 1 | a_l >> 63;
        a_l = a_l << 1;
        if (a_h > b)
        {
            a_h -= b;
            a_l |= 1;
        }
    }
    *q = a_l;
    *r = a_h;
}
#endif

NSROOT::Integer64::Integer64(uint64_t n)
{
    if (n == 0)
    {
        this->sign = 0;
        this->number = 0;
    }
    this->sign = 1;
    this->number = n;
}
NSROOT::Integer64::Integer64(int64_t n)
{
    if (n == 0)
    {
        this->sign = 0;
        this->number = 0;
    }
    else if (n > 0)
    {
        this->sign = 1;
        this->number = static_cast<uint64_t>(n);
    }
    else
    {
        this->sign = -1;
        this->number = static_cast<uint64_t>(-n);
    }
}

bool NSROOT::Integer64::operator==(const Integer64& other) const noexcept
{
    return sign == other.sign && number == other.number;
}

size_t std::hash<NSROOT::Integer64>::operator()(const NSROOT::Integer64& value) const
{
    size_t h0 = std::hash<char>{}(value.sign);
    size_t h1 = std::hash<uint64_t>{}(value.number);
    return dog_torch::utils::hash::combine(h0, h1);
}

NSROOT::UnsignedInteger128::UnsignedInteger128() : high_(0), low_(0) {}
NSROOT::UnsignedInteger128::UnsignedInteger128(uint64_t high, uint64_t low) : high_(high), low_(low) {}
NSROOT::UnsignedInteger128::UnsignedInteger128(uint64_t low) : high_(0), low_(low) {}

NSROOT::UnsignedInteger128::UnsignedInteger128(const UnsignedInteger128& other) : high_(other.high_), low_(other.low_) {}
NSROOT::UnsignedInteger128& NSROOT::UnsignedInteger128::operator=(const UnsignedInteger128& other)
{
    this->high_ = other.high_;
    this->low_ = other.low_;
    return *this;
}
NSROOT::UnsignedInteger128::UnsignedInteger128(UnsignedInteger128&& other) noexcept : high_(other.high_), low_(other.low_) {}
NSROOT::UnsignedInteger128& NSROOT::UnsignedInteger128::operator=(UnsignedInteger128&& other) noexcept
{
    if (this == &other) return *this;
    this->high_ = other.high_;
    this->low_ = other.low_;
    return *this;
}

NSROOT::CompareResult NSROOT::UnsignedInteger128::compare(const UnsignedInteger128& a, const UnsignedInteger128& b) noexcept
{
    if (a.high_ < b.high_)
        return CompareResult::LESS;
    if (a.high_ > b.high_)
        return CompareResult::GREATER;
    if (a.low_ < b.low_)
        return CompareResult::LESS;
    if (a.low_ > b.low_)
        return CompareResult::GREATER;
    return CompareResult::EQUAL;
}


bool NSROOT::UnsignedInteger128::operator==(const UnsignedInteger128& other) const noexcept
{
    return compare(*this, other) == CompareResult::EQUAL;
}
bool NSROOT::UnsignedInteger128::operator!=(const UnsignedInteger128& other) const noexcept
{
    return compare(*this, other) != CompareResult::EQUAL;
}
bool NSROOT::UnsignedInteger128::operator<(const UnsignedInteger128& other) const noexcept
{
    return compare(*this, other) == CompareResult::LESS;
}
bool NSROOT::UnsignedInteger128::operator>(const UnsignedInteger128& other) const noexcept
{
    return compare(*this, other) == CompareResult::GREATER;
}
bool NSROOT::UnsignedInteger128::operator<=(const UnsignedInteger128& other) const noexcept
{
    return compare(*this, other) != CompareResult::GREATER;
}
bool NSROOT::UnsignedInteger128::operator>=(const UnsignedInteger128& other) const noexcept
{
    return compare(*this, other) != CompareResult::LESS;
}
bool NSROOT::UnsignedInteger128::operator()() const noexcept
{
    return high_ == 0 && low_ == 0;
}
bool NSROOT::UnsignedInteger128::operator!() const noexcept
{
    return high_ != 0 || low_ != 0;
}


NSROOT::UnsignedInteger128 NSROOT::UnsignedInteger128::operator~() const noexcept
{
    return UnsignedInteger128(~high_, ~low_);
}

NSROOT::UnsignedInteger128 NSROOT::UnsignedInteger128::operator&(const UnsignedInteger128& other) const noexcept
{
    return UnsignedInteger128(high_ & other.high_, low_ & other.low_);
}

NSROOT::UnsignedInteger128 NSROOT::UnsignedInteger128::operator|(const UnsignedInteger128& other) const noexcept
{
    return UnsignedInteger128(high_ | other.high_, low_ | other.low_);
}
NSROOT::UnsignedInteger128 NSROOT::UnsignedInteger128::operator^(const UnsignedInteger128& other) const noexcept
{
    return UnsignedInteger128(high_ ^ other.high_, low_ ^ other.low_);
}

NSROOT::UnsignedInteger128 NSROOT::UnsignedInteger128::operator<<(uint64_t shift) const noexcept
{
    if (shift >= 128)
    {
        return 0;
    }
    else if (shift >= 64)
    {
        return UnsignedInteger128(low_ << (shift - 64), 0);
    }
    else
    {
        return UnsignedInteger128((high_ << shift) | (low_ >> (64 - shift)), low_ << shift);
    }
}
NSROOT::UnsignedInteger128 NSROOT::UnsignedInteger128::operator>>(uint64_t shift) const noexcept
{
    if (shift >= 128)
    {
        return 0;
    }
    else if (shift >= 64)
    {
        return UnsignedInteger128(0, high_ >> (shift - 64));
    }
    else
    {
        return UnsignedInteger128(high_ >> shift, (low_ >> shift) | (high_ << (64 - shift)));
    }
}

NSROOT::UnsignedInteger128 NSROOT::UnsignedInteger128::operator+(const UnsignedInteger128& other) const noexcept
{
    UnsignedInteger128 result;
    uint64_t carry = 0;
    u64add(0, this->low_, other.low_, &carry, &result.low_);
    u64add(carry, this->high_, other.high_, &carry, &result.high_);
    return result;
}
void NSROOT::UnsignedInteger128::operator+=(const UnsignedInteger128& other) noexcept
{
    uint64_t carry = 0;
    u64add(0, this->low_, other.low_, &carry, &this->low_);
    u64add(carry, this->high_, other.high_, &carry, &this->high_);
}
void NSROOT::UnsignedInteger128::operator++() noexcept
{
    uint64_t carry = 1;
    u64add(carry, this->low_, 0, &carry, &this->low_);
    u64add(carry, this->high_, 0, &carry, &this->high_);
}
NSROOT::UnsignedInteger128 NSROOT::UnsignedInteger128::operator++(int) noexcept
{
    UnsignedInteger128 temp = *this;
    uint64_t carry = 1;
    u64add(carry, this->low_, 0, &carry, &this->low_);
    u64add(carry, this->high_, 0, &carry, &this->high_);
    return temp;
}
NSROOT::UnsignedInteger128 NSROOT::UnsignedInteger128::operator-(const UnsignedInteger128& other) const noexcept
{
    UnsignedInteger128 result;
    uint64_t borrow = 0;
    u64sub(0, this->low_, other.low_, &borrow, &result.low_);
    u64sub(borrow, this->high_, other.high_, &borrow, &result.high_);
    return result;
}
void NSROOT::UnsignedInteger128::operator-=(const UnsignedInteger128& other) noexcept
{
    uint64_t borrow = 0;
    u64sub(0, this->low_, other.low_, &borrow, &this->low_);
    u64sub(borrow, this->high_, other.high_, &borrow, &this->high_);
}
void NSROOT::UnsignedInteger128::operator--() noexcept
{
    uint64_t borrow = 1;
    u64sub(borrow, this->low_, 0, &borrow, &this->low_);
    u64sub(borrow, this->high_, 0, &borrow, &this->high_);
}
NSROOT::UnsignedInteger128 NSROOT::UnsignedInteger128::operator--(int) noexcept
{
    UnsignedInteger128 temp = *this;
    uint64_t borrow = 1;
    u64sub(borrow, this->low_, 0, &borrow, &this->low_);
    u64sub(borrow, this->high_, 0, &borrow, &this->high_);
    return temp;
}
NSROOT::UnsignedInteger128 NSROOT::UnsignedInteger128::operator*(const UnsignedInteger128& other) const noexcept
{
    uint64_t r0 = 0;
    uint64_t r1 = 0;
    uint64_t r2 = 0;
    uint64_t r3 = 0;
    uint64_t r4 = 0;
    uint64_t r5 = 0;
    u64mul(this->low_, other.low_, &r1, &r0);
    u64mul(this->high_, other.low_, &r3, &r2);
    u64mul(other.high_, this->low_, &r5, &r4);
    u64add(0, r1, r2, &r2, &r1);
    u64add(0, r1, r4, &r4, &r1);
    return UnsignedInteger128(r1, r0);

}
void NSROOT::UnsignedInteger128::operator*=(const UnsignedInteger128& other) noexcept
{
    uint64_t r0s = 0;
    uint64_t r1s = 0;
    u64mul(this->low_, other.low_, &this->high_, &this->low_);
    u64mul(this->high_, other.low_, &r1s, &r0s);
    u64add(0, this->high_, r0s, &r1s, &this->high_);
}

NSROOT::UnsignedInteger128 NSROOT::UnsignedInteger128::operator/(const UnsignedInteger128& other) const
{
    if (other == 0)
        throw DOG_EXCEPTION(array_to_view(ERROR_DIVIDE_BY_ZERO));
    else if (*this < other)
    {
        return 0;
    }
    else if (this->high_ == 0 && other.high_ == 0)
    {
        return UnsignedInteger128(this->low_ / other.low_);
    }
    else if (other.high_ == 0)
    {
        uint64_t this_high = this->high_;
        uint64_t res_high = this_high / other.low_;
        this_high %= other.low_;
        uint64_t res_low = 0;
        uint64_t res_r = 0;
        u128div(this_high, this->low_, other.low_, &res_low, &res_r);
        return UnsignedInteger128(res_high, res_low);
    }
    else
    {
        uint64_t max = this->high_ / other.high_ + 1;
        uint64_t min = 0;
        uint64_t now = max / 2;
        const UnsignedInteger128& a_ = *this;
        while (max - min > 1)
        {
            UnsignedInteger128 temp = other * now;
            if (temp > a_)                 max = now;
            else if (temp <= a_ - other)   min = now;
            else                           break;
            now = (max & min) + ((max ^ min) >> 1);
        }
        UnsignedInteger128 q{ 0,now };
        return q;
    }
}
NSROOT::UnsignedInteger128 NSROOT::UnsignedInteger128::operator%(const UnsignedInteger128& other) const
{
    if (other == 0)
        throw DOG_EXCEPTION(array_to_view(ERROR_DIVIDE_BY_ZERO));
    else if (*this < other)
    {
        return 0;
    }
    else if (this->high_ == 0 && other.high_ == 0)
    {
        return UnsignedInteger128(this->low_ % other.low_);
    }
    else if (other.high_ == 0)
    {
        uint64_t this_high = this->high_;
        uint64_t res_high = this_high / other.low_;
        this_high %= other.low_;
        uint64_t res_low = 0;
        uint64_t res_r = 0;
        u128div(this_high, this->low_, other.low_, &res_low, &res_r);
        return UnsignedInteger128(0, res_r);
    }
    else
    {
        uint64_t max = this->high_ / other.high_ + 1;
        uint64_t min = 0;
        uint64_t now = max / 2;
        const UnsignedInteger128& a_ = *this;
        while (max - min > 1)
        {
            UnsignedInteger128 temp = other * now;
            if (temp > a_)                 max = now;
            else if (temp <= a_ - other)   min = now;
            else                           break;
            now = (max & min) + ((max ^ min) >> 1);
        }
        return *this - (other * now);
    }
}

void NSROOT::BigUnsignedInteger::trims(vec64& num)
{
    while (num.size() > 1 && num.back() == 0)
    {
        num.pop_back();
    }
    if (num.size() == 0)
    {
        num.push_back(0);
    }
}
NSROOT::BigUnsignedInteger::BigUnsignedInteger() : num_{ 0 } {};
NSROOT::BigUnsignedInteger::BigUnsignedInteger(const vec64& num) : num_(num)
{
    trims(this->num_);
}
NSROOT::BigUnsignedInteger::BigUnsignedInteger(vec64&& num) : num_(std::move(num))
{
    trims(this->num_);
}
NSROOT::BigUnsignedInteger::BigUnsignedInteger(uint64_t n)
{
    this->num_.push_back(n);
}

NSROOT::BigUnsignedInteger::BigUnsignedInteger(const BigUnsignedInteger& other) : num_(other.num_) {};
NSROOT::BigUnsignedInteger& NSROOT::BigUnsignedInteger::operator=(const BigUnsignedInteger& other)
{
    num_ = other.num_;
    return *this;
}
NSROOT::BigUnsignedInteger::BigUnsignedInteger(BigUnsignedInteger&& other) noexcept : num_(std::move(other.num_)) {};
NSROOT::BigUnsignedInteger& NSROOT::BigUnsignedInteger::operator=(BigUnsignedInteger&& other) noexcept
{
    if (this == &other) return *this;
    this->num_ = std::move(other.num_); return *this;
}

NSROOT::BigUnsignedInteger::BigUnsignedInteger(std::string_view str, uint64_t radix)
{
    uint64_t len = str.size();
    std::vector<uint32_t> buf32;
    if (radix != 2 && radix != 8 && radix != 10 && radix != 16)
    {
        throw DOG_EXCEPTION(array_to_view(ERROR_UNEXPECT_RADIX));
    }
    else if (radix == 2 || radix == 8 || radix == 16)
    {
        uint64_t buf = 0, now = 0;
        uint8_t buf_size = 0, buf_add = (radix == 2) ? 1 : (radix == 8 ? 3 : 4);
        buf32.reserve(len / buf_add + 1);
        for (uint64_t i = len - 1;; --i)
        {
            if (str[i] >= '0' && str[i] <= '1' && radix == 2)
            {
                now = str[i] - '0';
            }
            else if (str[i] >= '0' && str[i] <= '7' && radix == 8)
            {
                now = str[i] - '0';
            }
            else if (str[i] >= '0' && str[i] <= '9' && radix == 16)
            {
                now = str[i] - '0';
            }
            else if (str[i] >= 'a' && str[i] <= 'f' && radix == 16)
            {
                now = str[i] - 'a' + 10;
            }
            else if (str[i] >= 'A' && str[i] <= 'F' && radix == 16)
            {
                now = str[i] - 'A' + 10;
            }
            else
            {
                if (radix == 2)
                    throw DOG_EXCEPTION(array_to_view(ERROR_RADIX_UNEXPECT_CHAR_2));
                else if (radix == 8)
                    throw DOG_EXCEPTION(array_to_view(ERROR_RADIX_UNEXPECT_CHAR_8));
                else
                    throw DOG_EXCEPTION(array_to_view(ERROR_RADIX_UNEXPECT_CHAR_16));
            }
            buf |= now << buf_size;
            buf_size += buf_add;
            if (buf_size >= 32)
            {
                buf32.push_back(static_cast<uint32_t>(buf));
                buf >>= 32;
                buf_size -= 32;
            }
            if (i == 0) break;
        }
        if (buf_size != 0)
        {
            buf32.push_back(static_cast<uint32_t>(buf));
        }
    }
    else if (radix == 10)
    {
        constexpr uint64_t r = ((uint64_t)1) << 32;
        std::vector<uint8_t> mid_p(len);
        for (uint64_t i = 0; i < len; ++i)
        {
            char c = str[i];
            if (c < '0' || c > '9')
                throw DOG_EXCEPTION(array_to_view(ERROR_RADIX_UNEXPECT_CHAR_10));
            mid_p[i] = c - '0';
        }
        uint64_t real_start = 0, now = 0, remainder = 0;
        while (real_start != len)
        {
            for (uint64_t i = real_start; i < len; ++i)
            {
                now = remainder * 10 + mid_p[i];
                mid_p[i] = static_cast<uint8_t>(now / r);
                remainder = now % r;
            }
            buf32.push_back(static_cast<uint32_t>(remainder));
            remainder = 0;
            now = 0;
            while (real_start < len && mid_p[real_start] == 0) ++real_start;
        }
    }
    uint64_t buffer64 = 0, buf_size = 0;
    for (auto& i : buf32)
    {
        buffer64 |= (uint64_t)i << buf_size;
        buf_size += 32;
        if (buf_size == 64)
        {
            this->num_.push_back(buffer64);
            buffer64 = 0;
            buf_size = 0;
        }
    }
    if (buf_size != 0) this->num_.push_back(buffer64);
    trims(num_);
}
NSROOT::BigUnsignedInteger::BigUnsignedInteger(const std::string& str, uint64_t radix) : BigUnsignedInteger(std::string_view(str), radix) {};
NSROOT::BigUnsignedInteger::BigUnsignedInteger(const char* str, uint64_t radix) : BigUnsignedInteger(std::string_view(str), radix) {};

NSROOT::CompareResult NSROOT::BigUnsignedInteger::v_compare(const vec64& a, const vec64& b) noexcept
{
    if (a.size() > b.size()) return CompareResult::GREATER;
    if (a.size() < b.size()) return CompareResult::LESS;
    for (uint64_t i = a.size() - 1; ; --i)
    {
        if (a[i] > b[i]) return CompareResult::GREATER;
        else if (a[i] < b[i]) return CompareResult::LESS;
        if (i == 0) return CompareResult::EQUAL;
    }
}
std::vector<uint8_t> NSROOT::BigUnsignedInteger::to_bytes(bool is_smaller) const
{
    std::vector<uint8_t> result;
    result.reserve(this->num_.size() * 8);
    for (auto& i : this->num_)
    {
        for (uint8_t j = 0; j < 8; ++j)
        {
            result.push_back(i >> (j * 8) & 0xFF);
        }
    }
    while (result.back() == 0 && result.size() > 1)
    {
        result.pop_back();
    }
    if (!is_smaller)
    {
        std::reverse(result.begin(), result.end());
    }
    return result;
}
NSROOT::BigUnsignedInteger NSROOT::BigUnsignedInteger::from_bytes(const std::vector<uint8_t>& bytes, bool is_smaller)
{
    vec64 num_;
    num_.reserve(bytes.size() / 8 + 1);
    if (is_smaller)
    {
        uint64_t buffer = 0;
        uint8_t buffer_size = 0;
        for (uint64_t i = 0; i < bytes.size(); ++i)
        {
            buffer |= static_cast<uint64_t>(bytes[i]) << (8 * buffer_size);
            buffer_size++;
            if (buffer_size == 8)
            {
                num_.push_back(buffer);
                buffer = 0;
                buffer_size = 0;
            }
        }
        if (buffer_size != 0)
        {
            num_.push_back(buffer);
        }
        trims(num_);
    }
    else
    {
        uint64_t buffer = 0;
        uint8_t buffer_size = bytes.size() % 8 == 0 ? 0 : 8 - bytes.size() % 8;
        for (uint64_t i = 0; i < bytes.size(); ++i)
        {
            buffer <<= 8;
            buffer |= bytes[i];
            buffer_size++;
            if (buffer_size == 8)
            {
                num_.push_back(buffer);
                buffer = 0;
                buffer_size = 0;
            }
        }
        if (buffer_size != 0)
        {
            num_.push_back(buffer);
        }
        std::reverse(num_.begin(), num_.end());
        trims(num_);
    }
    return { num_ };
}
bool NSROOT::BigUnsignedInteger::operator>(const BigUInt& b) const noexcept
{
    return v_compare(this->num_, b.num_) == CompareResult::GREATER;
}
bool NSROOT::BigUnsignedInteger::operator>=(const BigUInt& b) const noexcept
{
    return v_compare(this->num_, b.num_) != CompareResult::LESS;
}
bool NSROOT::BigUnsignedInteger::operator<(const BigUInt& b) const noexcept
{
    return v_compare(this->num_, b.num_) == CompareResult::LESS;
}
bool NSROOT::BigUnsignedInteger::operator<=(const BigUInt& b) const noexcept
{
    return v_compare(this->num_, b.num_) != CompareResult::GREATER;
}
bool NSROOT::BigUnsignedInteger::operator==(const BigUInt& b) const noexcept
{
    return v_compare(this->num_, b.num_) == CompareResult::EQUAL;
}
bool NSROOT::BigUnsignedInteger::operator!=(const BigUInt& b) const noexcept
{
    return v_compare(this->num_, b.num_) != CompareResult::EQUAL;
}

bool NSROOT::BigUnsignedInteger::operator()() const noexcept
{
    return this->num_.size() > 1 || this->num_.back() > 0;
}
bool NSROOT::BigUnsignedInteger::operator!() const noexcept
{
    return this->num_.size() == 1 && this->num_.back() == 0;
}

std::string NSROOT::BigUnsignedInteger::to_num_str(uint64_t radix, bool is_upper) const
{
    std::string str;
    if (this->num_.back() == 0)
    {
        return "0";
    }
    if (radix == 2)
    {
        str.reserve(this->num_.size() * 64);
        uint8_t i = 0;
        while (!(this->num_.back() >> (64 - 1 - i) & 1) && this->num_.back() != 0)
        {
            i++;
        }
        for (auto crit = this->num_.crbegin(); crit != this->num_.crend(); ++crit)
        {
            for (; i < 64; ++i)
            {
                str += '0' + (((*crit) >> (64 - 1 - i)) & 1);
            }
            i = 0;
        }
    }
    else if (radix == 8)
    {
        str.reserve(this->num_.size() * (64 / 3));
        uint8_t i = 0;
        while (!(this->num_.back() >> (64 - 1 - i) & 1))
        {
            i++;
        }
        uint8_t buf = 0, buf_size = 3 - ((this->num_.size() * 64) - i) % 3;
        buf_size = buf_size == 3 ? 0 : buf_size;
        for (auto crit = this->num_.crbegin(); crit != this->num_.crend(); ++crit)
        {
            for (; i < 64; ++i)
            {
                buf |= (((*crit) >> (64 - 1 - i)) & 1) << (2 - buf_size);
                buf_size++;
                if (buf_size >= 3)
                {
                    str += '0' + (buf & 7);
                    buf >>= 3;
                    buf_size -= 3;
                }
            }
            i = 0;
        }
    }
    else if (radix == 16)
    {
        const char* hex = is_upper ? "0123456789ABCDEF" : "0123456789abcdef";
        str.reserve(this->num_.size() * 8);
        uint8_t i = 0;
        while (!(this->num_.back() >> (64 - 4 - i) & 0xF))
        {
            i += 4;
        }
        for (auto crit = this->num_.crbegin(); crit != this->num_.crend(); ++crit)
        {
            for (; i < 64; i += 4)
            {
                str += hex[(((*crit) >> (64 - 4 - i)) & 0xF)];
            }
            i = 0;
        }
    }
    else if (radix == 10)
    {
        str.reserve(static_cast<uint64_t>(this->num_.size() * 2.5));
        vec64 num = this->num_;
        while (v_compare(num, vec64({ 0 })) != CompareResult::EQUAL)
        {
            auto q_r = v_divide_single(num, 10);
            str.push_back(static_cast<char>('0' + q_r.second));
            num = q_r.first;
        }
        for (uint64_t in_size = 0; in_size < str.size() / 2; ++in_size)
        {
            std::swap(str[in_size], str[str.size() - 1 - in_size]);
        }
        uint64_t pos = 0;
        while (str[pos] == '0') ++pos;
        str = str.substr(pos);
    }
    else
    {
        throw DOG_EXCEPTION(array_to_view(ERROR_UNEXPECT_RADIX));
    }
    return str;
}

std::vector<uint64_t> NSROOT::BigUnsignedInteger::v_not(const vec64& num)
{
    vec64 result(num.size());
    for (uint64_t i = 0; i < num.size(); ++i)
    {
        result[i] = ~num[i];
    }
    trims(result);
    return result;
}
NSROOT::BigUnsignedInteger NSROOT::BigUnsignedInteger::operator~() const
{
    return BigUInt(v_not(this->num_));
}
std::vector<uint64_t> NSROOT::BigUnsignedInteger::v_and(const vec64& a, const vec64& b)
{
    const vec64& great = a.size() > b.size() ? a : b;
    const vec64& small = a.size() <= b.size() ? a : b;
    uint64_t g_len = great.size(), s_len = small.size();
    vec64 result(s_len);
    for (uint64_t i = 0; i < s_len; ++i)
    {
        result[i] = great[i] & small[i];
    }
    trims(result);
    return result;
}
NSROOT::BigUnsignedInteger NSROOT::BigUnsignedInteger::operator&(const BigUInt& other)
{
    return BigUInt(v_and(this->num_, other.num_));
}
std::vector<uint64_t> NSROOT::BigUnsignedInteger::v_or(const vec64& a, const vec64& b)
{
    const vec64& great = a.size() > b.size() ? a : b;
    const vec64& small = a.size() <= b.size() ? a : b;
    uint64_t g_len = great.size(), s_len = small.size(), i = 0;
    vec64 result(g_len);
    for (; i < s_len; ++i)
    {
        result[i] = great[i] | small[i];
    }
    for (; i < s_len; ++i)
    {
        result[i] = great[i];
    }
    trims(result);
    return result;
}
NSROOT::BigUnsignedInteger NSROOT::BigUnsignedInteger::operator|(const BigUInt& other)
{
    return BigUInt(v_or(this->num_, other.num_));
}
std::vector<uint64_t> NSROOT::BigUnsignedInteger::v_xor(const vec64& a, const vec64& b)
{
    const vec64& great = a.size() > b.size() ? a : b;
    const vec64& small = a.size() <= b.size() ? a : b;
    uint64_t g_len = great.size(), s_len = small.size();
    vec64 result(s_len);
    for (uint64_t i = 0; i < s_len; ++i)
    {
        result[i] = great[i] & small[i];
    }
    trims(result);
    return result;
}
NSROOT::BigUnsignedInteger NSROOT::BigUnsignedInteger::operator^(const BigUInt& other)
{
    return BigUInt(v_xor(this->num_, other.num_));
}

std::vector<uint64_t> NSROOT::BigUnsignedInteger::v_add(const vec64& a, const vec64& b) noexcept
{
    const vec64& great = a.size() > b.size() ? a : b;
    const vec64& small = a.size() <= b.size() ? a : b;
    uint64_t g_len = great.size(), s_len = small.size();
    uint64_t now = 0, carry = 0, i = 0;
    vec64 result(g_len + 1);
    for (; i < s_len; ++i)
    {
        u64add(carry, great[i], small[i], &carry, &now);
        result[i] = now;
    }
    for (; i < g_len; ++i)
    {
        u64add(carry, great[i], 0, &carry, &now);
        result[i] = now;
    }
    result[g_len] = carry;
    trims(result);
    return result;
}
void NSROOT::BigUnsignedInteger::v_add_self(const vec64& a, const vec64& b, vec64& result) noexcept
{
    const vec64& great = a.size() > b.size() ? a : b;
    const vec64& small = a.size() <= b.size() ? a : b;
    uint64_t g_len = great.size(), s_len = small.size();
    uint64_t now = 0, carry = 0, i = 0;
    result.resize(g_len + 1);
    for (; i < s_len; ++i)
    {
        u64add(carry, great[i], small[i], &carry, &now);
        result[i] = now;
    }
    for (; i < g_len; ++i)
    {
        u64add(carry, great[i], 0, &carry, &now);
        result[i] = now;
    }
    result[g_len] = carry;
    trims(result);
}
NSROOT::BigUnsignedInteger NSROOT::BigUnsignedInteger::operator+(const BigUInt& a) const noexcept
{
    return BigUInt(v_add(this->num_, a.num_));
}
void NSROOT::BigUnsignedInteger::operator+=(const BigUInt& a) noexcept
{
    v_add_self(this->num_, a.num_, this->num_);
}
void NSROOT::BigUnsignedInteger::operator++() noexcept
{
    v_add_self(this->num_, vec64{1}, this->num_);
}
NSROOT::BigUnsignedInteger NSROOT::BigUnsignedInteger::operator++(int) noexcept
{
    BigUInt temp = *this;
    v_add_self(this->num_, vec64{1}, this->num_);
    return temp;
}

std::vector<uint64_t> NSROOT::BigUnsignedInteger::v_subtract(const vec64& a, const vec64& b)
{
    if (v_compare(a, b) == CompareResult::LESS) throw DOG_EXCEPTION(ERROR_UNSIGNED_SUBTRACT_LESS);
    uint64_t g_len = a.size(), s_len = b.size();
    uint64_t now = 0, borrow = 0, i = 0;
    vec64 result(g_len);
    for (; i < s_len; ++i)
    {
        u64sub(borrow, a[i], b[i], &borrow, &now);
        result[i] = now;
    }
    for (; i < g_len; ++i)
    {
        u64sub(borrow, a[i], 0, &borrow, &now);
        result[i] = now;
    }
    trims(result);
    return result;
}
NSROOT::BigUnsignedInteger NSROOT::BigUnsignedInteger::operator-(const BigUInt& a) const
{
    return BigUInt(v_subtract(this->num_, a.num_));
}
void NSROOT::BigUnsignedInteger::operator-=(const BigUInt& a)
{
    this->num_ = v_subtract(this->num_, a.num_);
}
void NSROOT::BigUnsignedInteger::operator--()
{
    this->num_ = v_subtract(this->num_, vec64{1});
}
NSROOT::BigUnsignedInteger NSROOT::BigUnsignedInteger::operator--(int)
{
    BigUInt temp = *this;
    this->num_ = v_subtract(this->num_, vec64{1});
    return temp;
}

std::vector<uint64_t> NSROOT::BigUnsignedInteger::v_multiply_single(const vec64& a, uint64_t b, uint64_t exp) noexcept
{
    uint64_t now_h = 0, now_l = 0, carry = 0, i = 0;
    vec64 result(a.size() + 1 + exp);
    for (; i < a.size(); ++i)
    {
        u64mul(a[i], b, &now_h, &now_l);
        u64add(0, carry, now_l, &carry, &now_l);
        carry += now_h;
        result[exp + i] = now_l;
    }
    result[exp + i] = carry;
    trims(result);
    return result;
}
void NSROOT::BigUnsignedInteger::v_multiply_single_self(const vec64& a, uint64_t b, vec64& result, uint64_t exp) noexcept
{
    uint64_t now_h = 0, now_l = 0, carry = 0, i = 0;
    result.clear();
    result.resize(a.size() + 1 + exp, 0);
    for (; i < a.size(); ++i)
    {
        u64mul(a[i], b, &now_h, &now_l);
        u64add(0, carry, now_l, &carry, &now_l);
        carry += now_h;
        result[exp + i] = now_l;
    }
    result[exp + i] = carry;
    trims(result);
}
std::vector<uint64_t> NSROOT::BigUnsignedInteger::v_multiply_distributive(const vec64& a, const vec64& b) noexcept
{
    vec64 result, single;
    const vec64& great = a.size() > b.size() ? a : b;
    const vec64& small = a.size() <= b.size() ? a : b;
    result.reserve(great.size() + 1);
    single.reserve(great.size());
    for (uint64_t i = 0; i < small.size(); ++i)
    {
        v_multiply_single_self(great, small[i], single, i);
        v_add_self(result, single, result);
    }
    return result;
}
std::vector<uint64_t> NSROOT::BigUnsignedInteger::v_multiply(const vec64& a, const vec64& b) noexcept
{
    vec64 result;
    if (a == vec64{ 0 } || b == vec64{ 0 }) return { 0 };
    else if (a.size() == 1)
    {
        result = v_multiply_single(b, a[0]);
    }
    else if (b.size() == 1)
    {
        result = v_multiply_single(a, b[0]);
    }
    else
    {
        result = v_multiply_distributive(a, b);
    }
    trims(result);
    return result;
}
NSROOT::BigUnsignedInteger NSROOT::BigUnsignedInteger::operator*(const BigUInt& a) const noexcept
{
    return BigUInt(v_multiply(this->num_, a.num_));
}

std::pair<std::vector<uint64_t>, uint64_t> NSROOT::BigUnsignedInteger::v_divide_single(const vec64& a, uint64_t b)
{
    if (b == 0)
        throw DOG_EXCEPTION(array_to_view(ERROR_DIVIDE_BY_ZERO));
    uint64_t a_t_h = 0, a_t_l = 0, q = 0, i = a.size() - 1;
    vec64 result(a.size());
    for (auto rit = a.crbegin(); rit != a.crend(); ++rit)
    {
        a_t_l = *rit;
        u128div(a_t_h, a_t_l, b, &q, &a_t_h);
        result[i--] = q;
    }
    trims(result);
    return { result, a_t_h };
}
std::pair<std::vector<uint64_t>, std::vector<uint64_t>> NSROOT::BigUnsignedInteger::v_divide_knuth(const vec64& a, const vec64& b, bool recover_remainder)
{
    if (b.size() == 1 && b.back() == 0)
        throw DOG_EXCEPTION(array_to_view(ERROR_DIVIDE_BY_ZERO));
    uint64_t b_head = b.back();
    uint64_t d = 1;
    if (b_head < 0x7FFFFFFFFFFFFFFF)
        d = 0xFFFFFFFFFFFFFFFF / (b_head + 1);
    auto a_ = v_multiply_single(a, d);
    auto b_ = v_multiply_single(b, d);
    vec64 a_top(a_.end() - b_.size() + 1, a_.end());
    trims(a_top);
    b_head = b_.back();
    vec64 b_q, q(a_.size() - b_.size() + 1);
    auto q_location = q.rbegin();
    uint64_t a_head_l = 0, a_head_h = 0, q_set = 0, r_set = 0;
    for (uint64_t i = a_.size() - b_.size();; --i)
    {
        a_top.insert(a_top.begin(), a_[i]);
        trims(a_top);
        if (a_top.size() > b_.size())
        {
            a_head_h = *a_top.rbegin();
            a_head_l = *(a_top.rbegin() + 1);
        }
        else
        {
            a_head_h = 0;
            a_head_l = *a_top.rbegin();
        }
        u128div(a_head_h, a_head_l, b_head, &q_set, &r_set);
        v_multiply_single_self(b_, q_set, b_q);
        if (v_compare(a_top, b_q) != CompareResult::GREATER)
        {
            --q_set;
            b_q = v_subtract(b_q, b_);
        }
        if (v_compare(a_top, b_q) != CompareResult::GREATER)
        {
            --q_set;
            b_q = v_subtract(b_q, b_);
        }
        a_top = v_subtract(a_top, b_q);
        *q_location = q_set;
        ++q_location;
        if (i == 0) break;
    }
    trims(q);
    return { q, d == 1 && recover_remainder ? a_top : v_divide_single(a_top,d).first };
}
std::pair<std::vector<uint64_t>, std::vector<uint64_t>> NSROOT::BigUnsignedInteger::v_divide(const vec64& a, const vec64& b, bool recover_remainder)
{
    if (v_compare(b, { 0 }) == CompareResult::EQUAL) throw DOG_EXCEPTION(array_to_view(ERROR_DIVIDE_BY_ZERO));
    if (v_compare(a, { 0 }) == CompareResult::EQUAL) return { {0},{0} };
    if (v_compare(b, { 1 }) == CompareResult::EQUAL) return { a,{0} };
    auto com_r = v_compare(a, b);
    if (com_r == CompareResult::EQUAL) return { {1},{0} };
    if (com_r == CompareResult::LESS) return { {0},a };
    uint64_t max = std::max(a.size(), b.size());
    if (max == 1)
    {
        uint64_t q = a[0] / b[0];
        uint64_t r = a[0] % b[0];
        return { {q},{r} };
    }
    else if (b.size() == 1)
    {
        auto q_r = v_divide_single(a, b[0]);
        return { q_r.first,vec64{q_r.second} };
    }
    return v_divide_knuth(a, b, recover_remainder);
}
NSROOT::BigUnsignedInteger NSROOT::BigUnsignedInteger::operator/(const BigUInt& a) const
{
    return BigUInt(v_divide(this->num_, a.num_, false).first);
}
NSROOT::BigUnsignedInteger NSROOT::BigUnsignedInteger::operator%(const BigUInt& a) const
{
    return BigUInt(v_divide(this->num_, a.num_, true).second);
}

std::vector<uint64_t> NSROOT::BigUnsignedInteger::v_move_bit(const vec64& a, uint64_t n, bool is_right, bool allow_flow) noexcept
{
    if (n == 0) return a;
    uint64_t word_move = n / 64;
    if (word_move >= a.size() && !allow_flow) return { 0 };
    uint64_t bit_move = n % 64;
    uint64_t buf = 0, now = 0;
    vec64 res;
    if (is_right)
    {
        res.resize(a.size() - word_move);
        std::copy(a.begin() + word_move, a.end(), res.begin());
        if (bit_move != 0)
        {
            for (auto rit = res.rbegin(); rit != res.rend(); ++rit)
            {
                now = *rit;
                *rit = *rit >> bit_move | buf;
                buf = now << (64 - bit_move);
            }
        }
    }
    else
    {
        res.resize(allow_flow ? a.size() + word_move : a.size());
        std::copy(a.begin(), allow_flow ? a.end() : a.end() - word_move, res.begin() + word_move);
        if (bit_move != 0)
        {
            if (allow_flow) res.push_back(0);
            for (auto it = res.begin(); it != res.end(); ++it)
            {
                now = *it;
                *it = buf | *it << bit_move;
                buf = now >> (64 - bit_move);
            }
        }
    }
    trims(res);
    return res;
}
void NSROOT::BigUnsignedInteger::v_move_bit_self(vec64& a, uint64_t n, bool is_right, bool allow_flow) noexcept
{
    if (n == 0) return;
    uint64_t word_move = n / 64;
    if (word_move >= a.size() && !allow_flow)
    {
        a.clear();
        a.push_back(0);
        return;
    }
    uint64_t bit_move = n % 64;
    uint64_t buf = 0, now = 0;
    if (is_right)
    {
        std::move(a.begin() + word_move, a.end(), a.begin());
        std::fill(a.end() - word_move, a.end(), 0);
        if (bit_move != 0)
        {
            for (auto rit = a.rbegin(); rit != a.rend(); ++rit)
            {
                now = *rit;
                *rit = *rit >> bit_move | buf;
                buf = now << (64 - bit_move);
            }
        }
    }
    else
    {
        a.resize(a.size() + word_move);
        std::move(a.begin(), a.end() - word_move, a.begin() + word_move);
        std::fill(a.begin(), a.begin() + word_move, 0);
        if (bit_move != 0)
        {
            if (allow_flow) a.push_back(0);
            for (auto it = a.begin(); it != a.end(); ++it)
            {
                now = *it;
                *it = buf | *it << bit_move;
                buf = now >> (64 - bit_move);
            }
        }
    }
    trims(a);
}
NSROOT::BigUnsignedInteger NSROOT::BigUnsignedInteger::operator<<(uint64_t n) const noexcept
{
    return BigUInt(v_move_bit(this->num_, n, false, true));
}
void NSROOT::BigUnsignedInteger::operator<<=(uint64_t n) noexcept
{
    v_move_bit_self(this->num_, n, false, true);
}
NSROOT::BigUnsignedInteger NSROOT::BigUnsignedInteger::operator>>(uint64_t n) const noexcept
{
    return BigUInt(v_move_bit(this->num_, n, true, true));
}
void NSROOT::BigUnsignedInteger::operator>>=(uint64_t n) noexcept
{
    v_move_bit_self(this->num_, n, true, true);
}

NSROOT::BigInteger::BigInteger()
{
    this->num_ = 0;
    this->sign_ = 0;
}
NSROOT::BigInteger::BigInteger(const BigUnsignedInteger & num)
{
    this->num_ = num.num_;
    if (num == 0) this->sign_ = 0;
    else this->sign_ = 1;
}
NSROOT::BigInteger::BigInteger(char sign, const BigUnsignedInteger & num)
{
    this->num_ = num.num_;
    this->sign_ = sign;
    if (num == 0) this->sign_ = 0;
}
NSROOT::BigInteger::BigInteger(const BigInteger & other)
{
    this->sign_ = other.sign_;
    this->num_ = other.num_;
}
NSROOT::BigInteger& NSROOT::BigInteger::operator=(const BigInteger & other)
{
    this->sign_ = other.sign_;
    this->num_ = other.num_;
    return *this;
}
NSROOT::BigInteger::BigInteger(BigInteger&& other) noexcept
{
    this->num_ = std::move(other.num_);
    this->sign_ = other.sign_;
}
NSROOT::BigInteger& NSROOT::BigInteger::operator=(BigInteger && other) noexcept
{
    if (this == &other) return *this;
    this->num_ = std::move(other.num_);
    this->sign_ = other.sign_;
    return *this;
}
std::string NSROOT::BigInteger::to_num_str(uint64_t radix, bool is_upper) const
{
    std::string str = this->sign_ == -1 ? "-" : "";
    str += this->num_.to_num_str(radix, is_upper);
    return str;
}
NSROOT::BigInteger NSROOT::BigInteger::operator+(const BigInteger& other) const
{
    if (this->sign_ == other.sign_)
    {
        return BigInteger{ this->sign_,this->num_ + other.num_ };
    }
    else
    {
        if (this->num_ > other.num_)
        {
            return BigInteger{ this->sign_,this->num_ - other.num_ };
        }
        else if (this->num_ < other.num_)
        {
            return BigInteger{ other.sign_,other.num_ - this->num_ };
        }
        else
        {
            return BigInteger{ 0,0 };
        }
    }
}
NSROOT::BigInteger NSROOT::BigInteger::operator-() const
{
    return BigInteger{ static_cast<char>(-this->sign_) ,this->num_};
}
NSROOT::BigInteger NSROOT::BigInteger::operator-(const BigInteger& other) const
{
    return *this + (-other);
}
NSROOT::BigInteger NSROOT::BigInteger::operator*(const BigInteger& other) const
{
    return BigInteger{ static_cast<char>(other.sign_ * this->sign_),other.num_ * this->num_ };
}
NSROOT::BigInteger NSROOT::BigInteger::operator/(const BigInteger& other) const
{
    return BigInteger{ static_cast<char>(other.sign_ * this->sign_),other.num_ / this->num_ };
}
