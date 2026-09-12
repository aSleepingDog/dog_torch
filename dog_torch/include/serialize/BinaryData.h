#pragma once
#include "export.h"

#include <vector>
#include <string>
#include <random>

#include "utils/ctrans.h"
#include "utils/compile.h"
#include "math/number.h"
#include "utils/exception.h"

namespace dog_torch::serialize
{
    // !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~
    CPP_API std::string to_utf8(uint64_t code);
    class CPP_API BinaryData
    {
    private:
        using it = std::vector<uint8_t>::iterator;
        using cit = std::vector<uint8_t>::const_iterator;
        using rit = std::vector<uint8_t>::reverse_iterator;
        using crit = std::vector<uint8_t>::const_reverse_iterator;
        std::vector<uint8_t> data_;
    public:
        enum class Type : uint64_t
        {
            UTF8 = 0,
            Binary = 1,
            Hex = 2,
            Base64 = 3,
        };

        BinaryData();
        explicit BinaryData(uint64_t size);
        BinaryData(const std::vector<uint8_t>& data);
        BinaryData(std::vector<uint8_t>&& data);
        
        template<size_t N>
        BinaryData(const std::array<uint8_t, N>& data)
        {
            data_ = std::vector<uint8_t>(data.begin(), data.end());
        }

        BinaryData(std::string_view str, Type type);
        BinaryData(const std::string& str, Type type);
        BinaryData(const char* str, Type type);
        template<size_t N, Type Type>
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

        /**
         * @brief construct string from binary data
         * @brief 按原始字节序构造字符串
         * @example {0x41, 0x42, 0x43} -> "ABC"
         */
        std::string to_string() const;
        /**
         * @brief construct string with 0 and 1
         * @brief 按位构造字符串
         * @example {0x01, 0x42, 0x43} -> 000000010100001001000011
         */
        std::string to_bin_string() const;
        /**
         * @brief construct string by hexadecimal
         * @brief 按十六进制构造字符串
         * @example {0x01, 0x42, 0x43} -> 014243
         * @param is_upper is letter upper case? true upper|false lower
         * @param is_upper 遇到字母是否大写? true 大写|false 小写
         */
        std::string to_hex_string(bool is_upper) const;
        /**
         * @brief construct string by base64
         * @brief 按base64构造字符串
         * @param emplace_add replace '+' with char
         * @param emplace_add 替换 '+' 字符
         * @param emplace_handle replace '/' with char
         * @param emplace_add 替换 '/' 字符
         * @param emplace_equal replace '=' with char
         * @param emplace_add 替换 '=' 字符
         */
        std::string to_base64_string(char emplace_add = '+', char emplace_handle = '/', char emplace_equal = '=') const;

        //[start,end)
        /**
         * @brief cut by byte offset
         * @brief 按字节偏移量截取
         * @param start start byte offset
         * @param start 开始的字节偏移量
         * @param end end byte offset
         * @param end 结束的字节偏移量
         * @note stop at end if over length
         * @note 如果超过长度 则截取到末尾
        */
        BinaryData sub_bytes_pos(uint64_t start, uint64_t end) const;
        /**
         * @brief cut by byte const iterator
         * @brief 按字节常量迭代器截取
         * @param start start byte const iterator
         * @param start 开始的字节常量迭代器
         * @param end end byte const iterator
         * @param end 结束的字节常量迭代器
         */
        BinaryData sub_bytes_pos(cit start, cit end) const;
        /**
         * @brief cut by byte offset and length
         * @brief 按字节偏移量和长度截取
         * @param start start byte offset
         * @param start 开始的字节偏移量
         * @param length length
         * @param length 长度
         * @note stop at end if over length
         * @note 如果超过长度 则截取到末尾
         */
        BinaryData sub_bytes_len(uint64_t start, uint64_t length) const;
        /**
         * @brief cut by byte byte const iterator and length
         * @brief 按字节常量迭代器和长度截取
         * @param start start byte byte const iterator
         * @param start 开始的字节常量迭代器
         * @param length length
         * @param length 长度
         * @note stop at end if over length
         * @note 如果超过长度 则截取到末尾
         */
        BinaryData sub_bytes_len(cit start, uint64_t length) const;

        /**
         * @brief move bit
         * @brief 移位
         * @param is_right is right? true right|false left
         * @param is_right 是否右移? true 右移|false 左移
         * @param allow_resize allow resize? true resize|false not resize
         * @param allow_resize 是否允许调整大小? true 调整大小|false 不调整大小
         * @param shift shift count
         * @param shift 移位数量
         */
        BinaryData bit_move(bool is_right, bool allow_resize, uint64_t shift) const;
        /**
         * @brief move bit self
         * @brief 移位自身
         * @param is_right is right? true right|false left
         * @param is_right 是否右移? true 右移|false 左移
         * @param allow_resize allow resize? true resize|false not resize
         * @param allow_resize 是否允许调整大小? true 调整大小|false 不调整大小
         * @param shift shift count
         * @param shift 移位数量
         */
        void bit_move_self(bool is_right, bool allow_resize, uint64_t shift);
        BinaryData operator<<(uint64_t shift) const;
        void operator<<=(uint64_t shift);
        BinaryData operator>>(uint64_t shift) const;
        void operator>>=(uint64_t shift);

        /**
         * @brief cut by bit offset
         * @brief 按位偏移量截取
         * @param byte_start start byte offset
         * @param byte_start 开始的字节偏移量
         * @param bit_start start bit offset in start byte
         * @param bit_start 开始的字节中的位偏移量
         * @param byte_end end byte offset
         * @param byte_end 结束的字节偏移量
         * @param bit_end end bit offset in end byte
         * @param bit_end 结束的字节中的位偏移量
         * @note stop at end if over length
         * @note 如果超过长度 则截取到末尾
         */
        BinaryData sub_bits_pos(uint64_t byte_start, uint8_t bit_start, uint64_t byte_end, uint8_t bit_end) const;
        /**
         * @brief cut by bit offset
         * @brief 按位偏移量截取
         * @param byte_start start byte offset
         * @param byte_start 开始的字节偏移量
         * @param bit_start start bit offset in start byte
         * @param bit_start 开始的字节中的位偏移量
         * @param byte_end end byte offset
         * @param byte_end 结束的字节偏移量
         * @param bit_end end bit offset in end byte
         * @param bit_end 结束的字节中的位偏移量
         * @note stop at end if over length
         * @note 如果超过长度 则截取到末尾
         */
        BinaryData sub_bits_pos(cit byte_start, uint8_t bit_start, cit byte_end, uint8_t bit_end) const;
        /**
         * @brief cut by bit offset
         * @brief 按位偏移量截取
         * @param byte_start start byte offset
         * @param byte_start 开始的字节偏移量
         * @param bit_start start bit offset in start byte
         * @param bit_start 开始的字节中的位偏移量
         * @param length bit length
         * @param length 截取位长度
         * @note stop at end if over length
         * @note 如果超过长度 则截取到末尾
         */
        BinaryData sub_bits_len(uint64_t byte_start, uint8_t bit_start, uint64_t length) const;
        /**
         * @brief cut by bit offset
         * @brief 按位偏移量截取
         * @param byte_start start byte offset
         * @param byte_start 开始的字节偏移量
         * @param bit_start start bit offset in start byte
         * @param bit_start 开始的字节中的位偏移量
         * @param length bit length
         * @param length 截取位长度
         * @note stop at end if over length
         * @note 如果超过长度 则截取到末尾
         */
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

    class BinaryBuffer : public std::basic_streambuf<char>
    {
    private:
        BinaryData data_;
    public:
        BinaryBuffer(const BinaryData& data);

        int_type underflow() override;

        int_type uflow() override;

        std::streamsize xsgetn(char_type* s, std::streamsize count) override;

        std::streamsize showmanyc() override;
    };

    /**
     * @brief random read buffer
     * @brief 随机读缓冲区
     */
    class RandomBuffer : public std::basic_streambuf<char>
    {
    private:
        std::mt19937 rd;
        std::basic_streambuf<char>::traits_type::int_type peeked;
    public:
        RandomBuffer(uint64_t seed);

        int_type underflow() override;

        int_type uflow() override;

        std::streamsize xsgetn(char_type* s, std::streamsize count) override;

        std::streamsize showmanyc() override;
    };

    /**
     * @brief empty write buffer
     * @brief 空写缓冲区
     */
    class EmptyBuffer : public std::basic_streambuf<char>
    {
    public:
        EmptyBuffer();

        int_type overflow(int_type ch = traits_type::eof());
        std::streamsize xsputn(const char_type* s, std::streamsize count) override;
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