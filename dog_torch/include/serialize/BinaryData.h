#pragma once
#include "export.h"

#include <vector>
#include <string>

#include "utils/ctrans.h"
#include "utils/compile.h"
#include "math/number.h"
#include "utils/exception.h"

namespace dog_torch::serialize
{
    // !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~
    DOG_TORCH_API std::string to_utf8(uint64_t code);
    class DOG_TORCH_API BinaryData
    {
    private:
        using it = std::vector<uint8_t>::iterator;
        using cit = std::vector<uint8_t>::const_iterator;
        using rit = std::vector<uint8_t>::reverse_iterator;
        using crit = std::vector<uint8_t>::const_reverse_iterator;
        std::vector<uint8_t> data_;
    public:
        BinaryData();
        explicit BinaryData(uint64_t size);
        BinaryData(const std::vector<uint8_t>& data);
        BinaryData(std::vector<uint8_t>&& data);
        
        template<size_t N>
        BinaryData(const std::array<uint8_t, N>& data)
        {
            data_ = std::vector<uint8_t>(data.begin(), data.end());
        }

        BinaryData(std::string_view str, uint64_t type);
        BinaryData(const std::string& str, uint64_t type);
        BinaryData(const char* str, uint64_t type);
        template<size_t N, uint64_t Type>
        BinaryData(const std::array<char, N>& str) : BinaryData(dog_torch::utils::array_to_view(str), Type) {};

        BinaryData& operator=(uint64_t);

        BinaryData(const BinaryData& other);
        BinaryData& operator=(const BinaryData& other);
        BinaryData(BinaryData&& other) noexcept;
        BinaryData& operator=(BinaryData&& other) noexcept;

        ~BinaryData();

        void assign(uint64_t count, uint8_t elem);
        std::vector<uint8_t>::allocator_type get_allocator() const;

        std::vector<uint8_t>& get_data();
        const std::vector<uint8_t>& get_data() const;

        template<size_t N>
        std::array<uint8_t, N> to_array() const
        {
            return std::array<uint8_t, N>(data_.begin(), data_.begin() + N);
        }

        uint8_t* data_ptr();
        char* data_stream();
        const uint8_t* data_ptr() const;
        const int8_t* char_data_ptr() const;
        uint8_t& operator[](uint64_t index);
        const uint8_t& operator[](uint64_t index) const;
        uint8_t& at(uint64_t index);
        const uint8_t& at(uint64_t index) const;
        uint8_t& front();
        const uint8_t& front() const;
        uint8_t& back();
        const uint8_t& back() const;

        it begin();
        cit cbegin() const;
        it end();
        cit cend() const;
        rit rbegin();
        crit crbegin() const;
        crit rend();
        crit crend() const;

        uint64_t size() const;
        bool empty() const;
        uint64_t max_size() const;
        void reserve(uint64_t count);
        uint64_t capacity() const;
        void shrink_to_fit();

        void clear();
        it insert(it pos, uint8_t elem);
        it insert(it pos, uint64_t count, uint8_t elem);
        it insert(it pos, std::initializer_list<uint8_t> ilist);

        it emplace(it pos, uint8_t elem);

        it erase(it pos);
        it erase(cit pos);
        it erase(it first, it last);
        it erase(cit first, cit last);

        void push_back(uint8_t elem);
        void emplace_back(uint8_t elem);
        void pop_back();

        void resize(uint64_t count);
        void resize(uint64_t count, uint8_t elem);

        void swap(BinaryData& other);

        bool operator==(const BinaryData& other) const;
        bool operator!=(const BinaryData& other) const;

        std::string to_string() const;
        std::string to_bin_string() const;
        std::string to_hex_string(bool is_upper) const;
        std::string to_base64_string(char emplace_add, char emplace_handle, char emplace_equal) const;

        //[start,end)
        BinaryData sub_bytes_pos(uint64_t start, uint64_t end) const;
        BinaryData sub_bytes_pos(cit start, cit end) const;
        BinaryData sub_bytes_len(uint64_t start, uint64_t length) const;
        BinaryData sub_bytes_len(cit start, uint64_t length) const;

        BinaryData bit_move(bool is_right, bool allow_resize, uint64_t shift) const;
        void bit_move_self(bool is_right, bool allow_resize, uint64_t shift);
        BinaryData operator<<(uint64_t shift) const;
        void operator<<=(uint64_t shift);
        BinaryData operator>>(uint64_t shift) const;
        void operator>>=(uint64_t shift);

        BinaryData sub_bits_pos(uint64_t byte_start, uint8_t bit_start, uint64_t byte_end, uint8_t bit_end) const;
        BinaryData sub_bits_pos(cit byte_start, uint8_t bit_start, cit byte_end, uint8_t bit_end) const;
        BinaryData sub_bits_len(uint64_t byte_start, uint8_t bit_start, uint64_t length) const;
        BinaryData sub_bits_len(cit byte_start, uint8_t bit_start, uint64_t length) const;

        BinaryData bd_and(const BinaryData& other) const;
        BinaryData operator&(const BinaryData& other) const;
        BinaryData bd_or(const BinaryData& other) const;
        BinaryData operator|(const BinaryData& other) const;
        BinaryData bd_xor(const BinaryData& other) const;
        BinaryData operator^(const BinaryData& other) const;
        BinaryData bd_not() const;
        BinaryData operator~() const;

        void bd_and_self(const BinaryData& other);
        void operator&=(const BinaryData& other);
        void bd_or_self(const BinaryData& other);
        void operator|=(const BinaryData& other);
        void bd_xor_self(const BinaryData& other);
        void operator^=(const BinaryData& other);
        void bd_not_self();

        BinaryData operator+(const BinaryData& other) const;
        void operator+=(const BinaryData& other);
        void operator+=(uint8_t elem);
    };

    template<size_t N>
    constexpr std::array<uint8_t, N/2> from_hex(const char(&s)[N])
    {
        uint64_t size = N - 1;
        std::array<uint8_t, N / 2> data;
        auto trans = [](uint8_t c)->uint8_t
            {
                //static_assert(
                //    (c >= '0' && c <= '9') ||
                //    (c >= 'A' && c <= 'F') ||
                //    (c >= 'a' && c <= 'f'),
                //    "the char of hex string must is 0-9 A-F a-f");
                if (c >= '0' && c <= '9')
                {
                    return c - '0';
                }
                else if (c >= 'A' && c <= 'F')
                {
                    return c - 'A' + 10;
                }
                else if (c >= 'a' && c <= 'f')
                {
                    return c - 'a' + 10;
                }
                //else
                //{
                //    static_assert(false, "the char of hex string must is 0-9 A-F a-f");
                //}
                return 0;
            };
        uint64_t i = size % 2, pos = i;
        if (i)
        {
            data[0] = trans(s[0]);
        }
        for (; i < size; i += 2)
        {
            data[pos++] = trans(s[i]) << 4 | trans(s[i + 1]);
        }
        return data;
    }
}

#define NAMESPACE(name) dog_torch__serialize__##name
#define UTILS(name) dog_torch__utils__##name

extern "C"
{
    using NAMESPACE(BinaryData) = dog_torch::serialize::BinaryData;

    C_API(NAMESPACE(BinaryData)*) NAMESPACE(BinaryData_create_from_c_str)   (LVALUE(UTILS(CppResultSet)) result_set, const char* str, uint64_t type);
    C_API(NAMESPACE(BinaryData)*) NAMESPACE(BinaryData_create_from_string)  (LVALUE(UTILS(CppResultSet)) result_set, const LVALUE(UTILS(CppString)) str, uint64_t type);
    C_API(void)                   NAMESPACE(BinaryData_delete)              (NAMESPACE(BinaryData)** self);

    C_API(UTILS(CppString)*)      NAMESPACE(BinaryData_to_string)           (const LVALUE(NAMESPACE(BinaryData)) self);
    C_API(UTILS(CppString)*)      NAMESPACE(BinaryData_to_hex_string)       (const LVALUE(NAMESPACE(BinaryData)) self, uint8_t is_upper);
    C_API(UTILS(CppString)*)      NAMESPACE(BinaryData_to_base64_string)    (const LVALUE(NAMESPACE(BinaryData)) self, char a, char b, char c);

}

#undef NAMESPACE
#undef UTILS