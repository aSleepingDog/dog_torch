#pragma once
#include "export.h"

#include <vector>
#include <cstdint>
#include <string>
#include <algorithm>

#include "utils/compile.h"
#include "utils/exception.h"
#include "utils/hash.h"

// a + b + carry_in => carry|result
void u64add(uint64_t carry_in, uint64_t a, uint64_t b, uint64_t* carry, uint64_t* result);
// borrow|a - b - borrow_in => result
void u64sub(uint64_t borrow_in, uint64_t a, uint64_t b, uint64_t* borrow, uint64_t* result);
// a * b => result_high|result_low
void u64mul(uint64_t a, uint64_t b, uint64_t* result_high, uint64_t* result_low);
// a_h|a_l = b * q + r  a_h|a_l<=b*0xffffffffffffffff
void u128div(uint64_t a_h, uint64_t a_l, uint64_t b, uint64_t* q, uint64_t* r);

//__ == ::
#define NAMESPACE(func) dog_torch__math__number__##func


namespace dog_torch::math::number
{
    struct DOG_TORCH_API Integer64
    {
        char sign;
        uint64_t number;
        Integer64(uint64_t n);
        Integer64(int64_t n);
        bool operator==(const Integer64& other) const noexcept;
    };

    enum class DOG_TORCH_API CompareResult : char
    {
        EQUAL = 0,
        LESS = -1,
        GREATER = 1
    };

    class DOG_TORCH_API UnsignedInteger128
    {
    public:
        uint64_t high_;
        uint64_t low_;

        UnsignedInteger128();
        UnsignedInteger128(uint64_t high, uint64_t low);
        UnsignedInteger128(uint64_t low);

        UnsignedInteger128(const UnsignedInteger128& other);
        UnsignedInteger128& operator=(const UnsignedInteger128& other);
        UnsignedInteger128(UnsignedInteger128&& other) noexcept;
        UnsignedInteger128& operator=(UnsignedInteger128&& other) noexcept;

        static CompareResult compare(const UnsignedInteger128& a, const UnsignedInteger128& b) noexcept;

        bool operator==(const UnsignedInteger128& other) const noexcept;
        bool operator!=(const UnsignedInteger128& other) const noexcept;
        bool operator<(const UnsignedInteger128& other) const noexcept;
        bool operator>(const UnsignedInteger128& other) const noexcept;
        bool operator<=(const UnsignedInteger128& other) const noexcept;
        bool operator>=(const UnsignedInteger128& other) const noexcept;

        bool operator()() const noexcept;
        bool operator!() const noexcept;

        UnsignedInteger128 operator~() const noexcept;

        UnsignedInteger128 operator&(const UnsignedInteger128& other) const noexcept;

        UnsignedInteger128 operator|(const UnsignedInteger128& other) const noexcept;
        UnsignedInteger128 operator^(const UnsignedInteger128& other) const noexcept;

        UnsignedInteger128 operator<<(uint64_t shift) const noexcept;
        UnsignedInteger128 operator>>(uint64_t shift) const noexcept;

        UnsignedInteger128 operator+(const UnsignedInteger128& other) const noexcept;
        void operator+=(const UnsignedInteger128& other) noexcept;
        void operator++() noexcept;
        UnsignedInteger128 operator++(int) noexcept;
        UnsignedInteger128 operator-(const UnsignedInteger128& other) const noexcept;
        void operator-=(const UnsignedInteger128& other) noexcept;
        void operator--() noexcept;
        UnsignedInteger128 operator--(int) noexcept;
        UnsignedInteger128 operator*(const UnsignedInteger128& other) const noexcept;
        void operator*=(const UnsignedInteger128& other) noexcept;

        UnsignedInteger128 operator/(const UnsignedInteger128& other) const;
        UnsignedInteger128 operator%(const UnsignedInteger128& other) const;
    };

    class DOG_TORCH_API BigUnsignedInteger
    {
        using BigUInt = BigUnsignedInteger;
        using vec64 = std::vector<uint64_t>;
        using u64p = uint64_t*;
        using cu64p = const uint64_t*;
    public:
        vec64 num_;
        static void trims(vec64& num);

        BigUnsignedInteger();
        BigUnsignedInteger(const vec64& num);
        BigUnsignedInteger(vec64&& num);
        BigUnsignedInteger(uint64_t n);

        BigUnsignedInteger(const BigUnsignedInteger& other);
        BigUnsignedInteger& operator=(const BigUnsignedInteger& other);
        BigUnsignedInteger(BigUnsignedInteger&& other) noexcept;
        BigUnsignedInteger& operator=(BigUnsignedInteger&& other) noexcept;

        explicit BigUnsignedInteger(std::string_view str, uint64_t radix = 10);
        explicit BigUnsignedInteger(const std::string& str, uint64_t radix = 10);
        explicit BigUnsignedInteger(const char* str, uint64_t radix = 10);

        static CompareResult v_compare(const vec64& a, const vec64& b) noexcept;

        std::vector<uint8_t> to_bytes(bool is_smaller) const;
        static BigUnsignedInteger from_bytes(const std::vector<uint8_t>& bytes, bool is_smaller);

        bool operator>(const BigUInt& b) const noexcept;
        bool operator>=(const BigUInt& b) const noexcept;
        bool operator<(const BigUInt& b) const noexcept;
        bool operator<=(const BigUInt& b) const noexcept;
        bool operator==(const BigUInt& b) const noexcept;
        bool operator!=(const BigUInt& b) const noexcept;

        std::string to_num_str(uint64_t radix = 10, bool is_upper = false) const;

        bool operator()() const noexcept;
        bool operator!() const noexcept;

        static vec64 v_not(const vec64& num);
        BigUInt operator~() const;
        static vec64 v_and(const vec64& a, const vec64& b);
        BigUInt operator&(const BigUInt& other);
        static vec64 v_or(const vec64& a, const vec64& b);
        BigUInt operator|(const BigUInt& other);
        static vec64 v_xor(const vec64& a, const vec64& b);
        BigUInt operator^(const BigUInt& other);


        static vec64 v_add(const vec64& a, const vec64& b) noexcept;
        static void v_add_self(const vec64& a, const vec64& b, vec64& result) noexcept;
        BigUInt operator+(const BigUInt& a) const noexcept;
        void operator+=(const BigUInt& a) noexcept;
        void operator++() noexcept;
        BigUInt operator++(int) noexcept;

        static vec64 v_subtract(const vec64& a, const vec64& b);
        BigUInt operator-(const BigUInt& a) const;
        void operator-=(const BigUInt& a);
        void operator--();
        BigUInt operator--(int);

        static vec64 v_multiply_single(const vec64& a, uint64_t b, uint64_t exp = 0) noexcept;
        static void v_multiply_single_self(const vec64& a, uint64_t b, vec64& result, uint64_t exp = 0) noexcept;
        static vec64 v_multiply_distributive(const vec64& a, const vec64& b) noexcept;
        static vec64 v_multiply(const vec64& a, const vec64& b) noexcept;
        BigUInt operator*(const BigUInt& a) const noexcept;

        static std::pair<vec64, uint64_t> v_divide_single(const vec64& a, uint64_t b);
        static std::pair<vec64, vec64> v_divide_knuth(const vec64& a, const vec64& b, bool recover_remainder = true);
        static std::pair<vec64, vec64> v_divide(const vec64& a, const vec64& b, bool recover_remainder = true);
        BigUInt operator/(const BigUInt& b) const;
        BigUInt operator%(const BigUInt& b) const;

        static vec64 v_move_bit(const vec64& a, uint64_t n, bool is_right, bool allow_flow) noexcept;
        static void v_move_bit_self(vec64& a, uint64_t n, bool is_right, bool allow_flow) noexcept;
        BigUInt operator<<(uint64_t n) const noexcept;
        void operator<<=(uint64_t n) noexcept;
        BigUInt operator>>(uint64_t n) const noexcept;
        void operator>>=(uint64_t n) noexcept;

    };
}
namespace std
{
    template<>
    struct hash<dog_torch::math::number::Integer64>
    {
        size_t operator()(const dog_torch::math::number::Integer64& value) const;
    };
}
#undef NAMESPACE

