#include "serialize/BinaryData.h"

namespace NSROOT = dog_torch::serialize;

using dog_torch::utils::from_c_str;

using dog_torch::utils::array_to_view;

constexpr auto ERROR_UNEXPECT_CHAR = from_c_str("unexcept char");
constexpr auto ERROR_WRONG_FORMAT = from_c_str("unexcept format");
constexpr auto ERROR_UNEXPECT_TYPE = from_c_str("unexcept type");

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

NSROOT::BinaryData::BinaryData()
{}
NSROOT::BinaryData::BinaryData(uint64_t size)
{
    this->data_.resize(size, 0);
}
NSROOT::BinaryData::BinaryData(const std::vector<uint8_t>&data)
{
    this->data_ = data;
}
NSROOT::BinaryData::BinaryData(std::vector<uint8_t> && data)
{
    this->data_ = std::move(data);
}
NSROOT::BinaryData::BinaryData(std::string_view str, uint64_t type)
{
    uint64_t size = str.size();
    if (type == 0)//ORI
    {
        this->data_.resize(size);
        this->data_.assign(str.begin(), str.end());
    }
    else if (type == 1)//Bin
    {
        auto trans = [](uint8_t c)
            {
                if (c != '0' && c != '1')
                {
                    throw DOG_EXCEPTION(array_to_view(ERROR_UNEXPECT_CHAR));
                }
                return c - '0';
            };
        uint64_t i = size % 8, pos = i > 0 ? 1 : 0;
        this->data_.resize((size / 8) + pos);
        for (; i < 8; i++)
        {
            this->data_[0] <<= 1;
            this->data_[0] |= trans(str[0]);
        }
        for (i = 8; i < size; i += 8)
        {
            for (uint64_t j = 0; j < 8; j++)
            {
                this->data_[pos] <<= 1;
                this->data_[pos] |= trans(str[i + j]);
            }
            ++pos;
        }
    }
    else if (type == 2)//Hex
    {
        auto trans = [](uint8_t c)->uint8_t
            {
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
                throw DOG_EXCEPTION(array_to_view(ERROR_UNEXPECT_CHAR));
            };
        uint64_t i = size % 2, pos = i;
        if (i)
        {
            this->data_.resize((size / 2) + 1);
            this->data_[0] = trans(str[0]);
        }
        else
        {
            this->data_.resize(size / 2);
        }
        for (; i < size; i += 2)
        {
            this->data_[pos++] = trans(str[i]) << 4 | trans(str[i + 1]);
        }
    }
    else if (type == 3)//Base64
    {
        auto trans = [](uint8_t c, bool is_end)->uint8_t
            {
                if (c >= '0' && c <= '9')
                {
                    return c - '0' + 52;
                }
                else if (c >= 'A' && c <= 'Z')
                {
                    return c - 'A';
                }
                else if (c >= 'a' && c <= 'z')
                {
                    return c - 'a' + 26;
                }
                else if (c == '+')
                {
                    return 62;
                }
                else if (c == '/')
                {
                    return 63;
                }
                else if (c == '=' && is_end)
                {
                    return 0xff;
                }
                throw DOG_EXCEPTION(array_to_view(ERROR_UNEXPECT_CHAR));
            };
        if (size % 4 != 0)
        {
            throw DOG_EXCEPTION(array_to_view(ERROR_WRONG_FORMAT));
        }
        this->data_.reserve((size / 4) * 3);
        uint64_t i = 0;
        uint8_t b1 = 0, b2 = 0, b3 = 0, b4 = 0, r1 = 0, r2 = 0, r3 = 0;
        for (i = 0; i < size - 4; i += 4)
        {
            b1 = trans(str[i], false);
            b2 = trans(str[i + 1], false);
            b3 = trans(str[i + 2], false);
            b4 = trans(str[i + 3], false);

            r1 = b1 << 2 | b2 >> 4;
            r2 = b2 << 4 | b3 >> 2;
            r3 = b3 << 6 | b4;

            this->data_.push_back(r1);
            this->data_.push_back(r2);
            this->data_.push_back(r3);
        }
        b1 = trans(str[i], true);
        b2 = trans(str[i + 1], true);
        b3 = trans(str[i + 2], true);
        b4 = trans(str[i + 3], true);
        r1 = b1 << 2 | b2 >> 4;
        this->data_.push_back(r1);
        if (b3 != 0xff)
        {
            r2 = b2 << 4 | b3 >> 2;
            this->data_.push_back(r2);
        }
        if (b4 != 0xff)
        {
            r3 = b3 << 6 | b4;
            this->data_.push_back(r3);
        }
    }
    else
    {
        throw DOG_EXCEPTION(array_to_view(ERROR_WRONG_FORMAT));
    }
}
NSROOT::BinaryData::BinaryData(const std::string& str, uint64_t type) : BinaryData(std::string_view(str), type) {};
NSROOT::BinaryData::BinaryData(const char* str, uint64_t type) : BinaryData(std::string_view(str), type) {};
NSROOT::BinaryData::BinaryData(const BinaryData & other)
{
    this->data_ = other.data_;
}
NSROOT::BinaryData& NSROOT::BinaryData::operator=(const BinaryData & other)
{
    this->data_ = other.data_;
    return *this;
}
NSROOT::BinaryData::BinaryData(BinaryData&& other) noexcept
{
    this->data_ = std::move(other.data_);
}
NSROOT::BinaryData& NSROOT::BinaryData::operator=(BinaryData && other) noexcept
{
    if (this == &other) return *this;
    this->data_ = std::move(other.data_);
    return *this;
}

NSROOT::BinaryData::~BinaryData()
{
    std::fill(this->data_.begin(), this->data_.end(), 0);
}

void NSROOT::BinaryData::assign(uint64_t count, uint8_t elem)
{
    this->data_.assign(count, elem);
}
std::vector<uint8_t>::allocator_type NSROOT::BinaryData::get_allocator() const
{
    return this->data_.get_allocator();
}

std::vector<uint8_t>& NSROOT::BinaryData::get_data()
{
    return this->data_;
}
const std::vector<uint8_t>& NSROOT::BinaryData::get_data() const
{
    return this->data_;
}

const uint8_t* NSROOT::BinaryData::data_ptr() const
{
    return this->data_.data();
}
const int8_t* NSROOT::BinaryData::char_data_ptr() const
{
    return (const int8_t*)this->data_.data();
}
uint8_t* NSROOT::BinaryData::data_ptr()
{
    return this->data_.data();
}
char* dog_torch::serialize::BinaryData::data_stream()
{
    return (char*)this->data_.data();
}
uint8_t& NSROOT::BinaryData::operator[](uint64_t index)
{
    return this->data_[index];
}
const uint8_t& NSROOT::BinaryData::operator[](uint64_t index) const
{
    return this->data_[index];
}
uint8_t& NSROOT::BinaryData::at(uint64_t index)
{
    return this->data_.at(index);
}
const uint8_t& NSROOT::BinaryData::at(uint64_t index) const
{
    return this->data_.at(index);
}
uint8_t& NSROOT::BinaryData::front()
{
    return this->data_.front();
}
const uint8_t& NSROOT::BinaryData::front() const
{
    return this->data_.front();
}
uint8_t& NSROOT::BinaryData::back()
{
    return this->data_.back();
}
const uint8_t& NSROOT::BinaryData::back() const
{
    return this->data_.back();
}

NSROOT::BinaryData::it NSROOT::BinaryData::begin()
{
    return this->data_.begin();
}
NSROOT::BinaryData::cit NSROOT::BinaryData::cbegin() const
{
    return this->data_.cbegin();
}
NSROOT::BinaryData::it NSROOT::BinaryData::end()
{
    return this->data_.end();
}
NSROOT::BinaryData::cit NSROOT::BinaryData::cend() const
{
    return this->data_.cend();
}
NSROOT::BinaryData::rit NSROOT::BinaryData::rbegin()
{
    return this->data_.rbegin();
}
NSROOT::BinaryData::crit NSROOT::BinaryData::crbegin() const
{
    return this->data_.crbegin();
}
NSROOT::BinaryData::crit NSROOT::BinaryData::rend()
{
    return this->data_.rend();
}
NSROOT::BinaryData::crit NSROOT::BinaryData::crend() const
{
    return this->data_.crend();
}

uint64_t NSROOT::BinaryData::size() const
{
    return this->data_.size();
}

bool NSROOT::BinaryData::empty() const
{
    return this->data_.empty();
}
uint64_t NSROOT::BinaryData::max_size() const
{
    return this->data_.max_size();
}
void NSROOT::BinaryData::reserve(uint64_t count)
{
    return this->data_.reserve(count);
}
uint64_t NSROOT::BinaryData::capacity() const
{
    return this->data_.capacity();
}
void NSROOT::BinaryData::shrink_to_fit()
{
    this->data_.shrink_to_fit();
}

void NSROOT::BinaryData::clear()
{
    return this->data_.clear();
}
NSROOT::BinaryData::it NSROOT::BinaryData::insert(it pos, uint8_t elem)
{
    return this->data_.insert(pos, elem);
}
NSROOT::BinaryData::it NSROOT::BinaryData::insert(it pos, uint64_t count, uint8_t elem)
{
    return this->data_.insert(pos, count, elem);
}
NSROOT::BinaryData::it NSROOT::BinaryData::insert(it pos, std::initializer_list<uint8_t> ilist)
{
    return this->data_.insert(pos, ilist);
}
NSROOT::BinaryData::it NSROOT::BinaryData::emplace(it pos, uint8_t elem)
{
    return this->data_.emplace(pos, elem);
}
NSROOT::BinaryData::it NSROOT::BinaryData::erase(it pos)
{
    return this->data_.erase(pos);
}
NSROOT::BinaryData::it NSROOT::BinaryData::erase(cit pos)
{
    return this->data_.erase(pos);
}
NSROOT::BinaryData::it NSROOT::BinaryData::erase(it first, it last)
{
    return this->data_.erase(first, last);
}
NSROOT::BinaryData::it NSROOT::BinaryData::erase(cit first, cit last)
{
    return this->data_.erase(first, last);
}
void NSROOT::BinaryData::push_back(uint8_t elem)
{
    this->data_.push_back(elem);
}
void NSROOT::BinaryData::emplace_back(uint8_t elem)
{
    this->data_.emplace_back(elem);
}
void NSROOT::BinaryData::pop_back()
{
    this->data_.pop_back();
}
void NSROOT::BinaryData::resize(uint64_t count)
{
    this->data_.resize(count);
}
void NSROOT::BinaryData::resize(uint64_t count, uint8_t elem)
{
    this->data_.resize(count, elem);
}
void NSROOT::BinaryData::swap(BinaryData & other)
{
    this->data_.swap(other.data_);
}

bool NSROOT::BinaryData::operator==(const BinaryData & other) const
{
    return this->data_ == other.data_;
}
bool NSROOT::BinaryData::operator!=(const BinaryData& other) const
{
    return this->data_ != other.data_;
}

std::string NSROOT::BinaryData::to_string() const
{
    return std::string(this->data_.begin(), this->data_.end());
}
std::string NSROOT::BinaryData::to_bin_string() const
{
    if(this->data_.empty()) return "";
    std::string result;
    result.reserve(this->data_.size() * 8);
    result += std::format("{:08b}", this->data_[0]);
    for (auto it = this->data_.begin() + 1; it != this->data_.end(); ++it)
    {
        result += std::format("{:08b}", *it);
    }
    return result;
}
std::string NSROOT::BinaryData::to_hex_string(bool is_upper) const
{
    if (this->data_.empty()) return "";
    const char* list = is_upper ? "0123456789ABCDEF" : "0123456789abcdef";
    uint8_t b = this->data_[0];
    std::string result;
    result.reserve(this->data_.size() * 2);
    for (auto it = this->data_.begin(); it != this->data_.end(); ++it)
    {
        result.push_back(list[*it >> 4]);
        result.push_back(list[*it & 0x0F]);
    }
    return result;
}
std::string NSROOT::BinaryData::to_base64_string(char emplace_add, char emplace_handle, char emplace_equal) const
{
    if (this->data_.empty()) return "";
    char list[66] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    list[62] = emplace_add;
    list[63] = emplace_handle;
    list[64] = emplace_equal;
    std::string result;
    result.reserve(this->data_.size() * 4 / 3);
    uint64_t i = 0;
    uint32_t buf = 0;
    for (; i + 2 < this->data_.size(); i += 3)
    {
        buf |= this->data_[i];
        buf <<= 8;
        buf |= this->data_[i + 1];
        buf <<= 8;
        buf |= this->data_[i + 2];
        result.push_back(list[(buf >> 18) & 0x3F]);
        result.push_back(list[(buf >> 12) & 0x3F]);
        result.push_back(list[(buf >> 6) & 0x3F]);
        result.push_back(list[buf & 0x3F]);
        buf = 0;
    }
    if (this->data_.size() - i == 1)
    {
        buf |= this->data_[i];
        buf <<= 16;
        result.push_back(list[(buf >> 18) & 0x3F]);
        result.push_back(list[(buf >> 12) & 0x3F]);
        result.push_back(list[64]);
        result.push_back(list[64]);
    }
    else if (this->data_.size() - i == 2)
    {
        buf |= this->data_[i];
        buf <<= 8;
        buf |= this->data_[i + 1];
        buf <<= 8;
        result.push_back(list[(buf >> 18) & 0x3F]);
        result.push_back(list[(buf >> 12) & 0x3F]);
        result.push_back(list[(buf >> 6) & 0x3F]);
        result.push_back(list[64]);
    }
    return result;
}

NSROOT::BinaryData NSROOT::BinaryData::sub_bytes_pos(uint64_t start, uint64_t end) const
{
    return BinaryData(std::vector<uint8_t>(this->data_.cbegin() + start, end >= this->size() ? this->cend() : this->data_.cbegin() + end));
}
NSROOT::BinaryData NSROOT::BinaryData::sub_bytes_pos(cit start, cit end) const
{
    return BinaryData(std::vector<uint8_t>(start, end));
}
NSROOT::BinaryData NSROOT::BinaryData::sub_bytes_len(uint64_t start, uint64_t length) const
{
    return BinaryData(std::vector<uint8_t>(
        this->data_.cbegin() + start, 
        start + length >= this->size() ? this->cend() : this->data_.cbegin() + start + length));
}
NSROOT::BinaryData NSROOT::BinaryData::sub_bytes_len(cit start, uint64_t length) const
{
    return BinaryData(std::vector<uint8_t>(start,
        start + length >= this->cend() ? this->cend() : start + length));
}

NSROOT::BinaryData NSROOT::BinaryData::bit_move(bool is_right, bool allow_resize, uint64_t shift) const
{
    if (shift == 0) return *this;
    uint64_t byte_shift = shift / 8;
    if (!allow_resize && byte_shift >= this->data_.size())
    {
        return BinaryData();
    }
    uint64_t bit_shift = shift % 8;
    uint8_t temp = 0, buf = 0;
    std::vector<uint8_t> result;
    if (is_right)
    {
        if (allow_resize)
        {
            result.resize(byte_shift + this->data_.size());
            std::copy(this->data_.cbegin(), this->data_.cend(), result.begin() + byte_shift);
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
            result.resize(this->data_.size() - byte_shift);
            std::copy(this->data_.cbegin(), this->data_.cend() - byte_shift, result.begin());
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
            result.resize(byte_shift + this->data_.size());
            std::copy(this->data_.cbegin(), this->data_.cend(), result.begin());
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
            result.resize(this->data_.size() - byte_shift);
            std::copy(this->data_.cbegin() + byte_shift, this->data_.cend(), result.begin());
            for (auto it = result.rbegin(); it != result.rend(); ++it)
            {
                temp = *it;
                *it = (temp << bit_shift) | buf;
                buf = temp >> (8 - bit_shift);
            }
        }
    }
    return BinaryData(result);
}
void NSROOT::BinaryData::bit_move_self(bool is_right, bool allow_resize, uint64_t shift)
{
    if (shift == 0) return;
    uint64_t byte_shift = shift / 8;
    if (!allow_resize && byte_shift >= this->data_.size())
    {
        this->data_.clear();
        return;
    }
    uint64_t bit_shift = shift % 8;
    uint8_t temp = 0, buf = 0;
    if (is_right)
    {
        if (allow_resize)
        {
            this->insert(this->begin(), byte_shift, 0);
            for (auto it = this->begin() + byte_shift; it != this->end(); ++it)
            {
                temp = *it;
                *it = (temp >> bit_shift) | buf;
                buf = temp << (8 - bit_shift);
            }
            if (buf)
            {
                this->data_.push_back(buf);
            }
        }
        else
        {
            std::move(this->data_.cbegin(), this->data_.cend() - byte_shift, this->data_.begin() + byte_shift);
            std::fill(this->data_.begin(), this->data_.begin() + byte_shift, 0);
            for (auto it = this->begin() + byte_shift; it != this->end(); ++it)
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
            for(uint64_t i = 0; i < byte_shift; ++i) this->data_.push_back(0);
            for (auto it = this->rbegin() + byte_shift; it != this->rend(); ++it)
            {
                temp = *it;
                *it = (temp << bit_shift) | buf;
                buf = temp >> (8 - bit_shift);
            }
            if (buf)
            {
                this->data_.insert(this->data_.cbegin(), buf);
            }
        }
        else
        {
            //for (uint64_t i = byte_shift; i < this->size(); ++i)
            //    this->at(i - byte_shift) = this->at(i);
            std::copy(this->begin() + byte_shift, this->end(), this->begin());
            std::fill(this->rbegin(), this->rbegin() + byte_shift, 0);
            for (auto it = this->rbegin() + byte_shift; it != this->rend(); ++it)
            {
                temp = *it;
                *it = (temp << bit_shift) | buf;
                buf = temp >> (8 - bit_shift);
            }
        }
    }
}

NSROOT::BinaryData dog_torch::serialize::BinaryData::operator<<(uint64_t shift) const
{
    return this->bit_move(false, true, shift);
}
void dog_torch::serialize::BinaryData::operator<<=(uint64_t shift)
{
    this->bit_move_self(false, true, shift);
}
NSROOT::BinaryData dog_torch::serialize::BinaryData::operator>>(uint64_t shift) const
{
    return this->bit_move(true, true, shift);
}
void dog_torch::serialize::BinaryData::operator>>=(uint64_t shift)
{
    this->bit_move_self(true, true, shift);
}

NSROOT::BinaryData NSROOT::BinaryData::sub_bits_pos(uint64_t byte_start, uint8_t bit_start, uint64_t byte_end, uint8_t bit_end) const
{
    if (bit_end > 0) byte_end++;
    BinaryData result = this->sub_bytes_pos(byte_start, byte_end);
    if (!result.size()) return result;
    uint8_t mask = bit_end > 0 ? 0xff << (8 - bit_end) : 0xff;
    result.back() &= mask;
    return result.bit_move(false, false, bit_start);
}
NSROOT::BinaryData NSROOT::BinaryData::sub_bits_pos(cit byte_start, uint8_t bit_start, cit byte_end, uint8_t bit_end) const
{
    if (bit_end > 0) byte_end++;
    BinaryData result = this->sub_bytes_pos(byte_start, byte_end);
    uint8_t mask = bit_end > 0 ? 0xff << (8 - bit_end) : 0xff;
    result.back() &= mask;
    return result.bit_move(false, false, bit_start);
}
NSROOT::BinaryData NSROOT::BinaryData::sub_bits_len(uint64_t byte_start, uint8_t bit_start, uint64_t length) const
{
    uint64_t byte_end = 
        byte_start + ((bit_start + length) / 8) < this->data_.size() ?
        byte_start + ((bit_start + length) / 8) : this->data_.size();
    uint8_t bit_end = 
        byte_start + ((bit_start + length) / 8) < this->data_.size() ?
        (bit_start + length) % 8 : 0;
    return this->sub_bits_pos(byte_start, bit_start, byte_end, bit_end);
}
NSROOT::BinaryData NSROOT::BinaryData::sub_bits_len(cit byte_start, uint8_t bit_start, uint64_t length) const
{
    cit byte_end =
        byte_start + ((bit_start + length) / 8) < this->data_.cend() ?
        byte_start + ((bit_start + length) / 8) : this->data_.cend();
    uint8_t bit_end =
        byte_start + ((bit_start + length) / 8) < this->data_.cend() ?
        (bit_start + length) % 8 : 0;
    return this->sub_bits_pos(byte_start, bit_start, byte_end, bit_end);
}

NSROOT::BinaryData NSROOT::BinaryData::bd_and(const BinaryData& other) const
{
    const std::vector<uint8_t>& great = this->data_.size() > other.data_.size() ? this->data_ : other.data_;
    const std::vector<uint8_t>& small = this->data_.size() <= other.data_.size() ? this->data_ : other.data_;
    std::vector<uint8_t> result(great.size(), 0);
    uint64_t i = 0;
    for (; i < small.size(); ++i)
    {
        result[i] = great[i] & small[i];
    }
    return BinaryData(result);
}
NSROOT::BinaryData NSROOT::BinaryData::operator&(const BinaryData& other) const
{
    return this->bd_and(other);
}
NSROOT::BinaryData NSROOT::BinaryData::bd_or(const BinaryData& other) const
{
    const std::vector<uint8_t>& great = this->data_.size() > other.data_.size() ? this->data_ : other.data_;
    const std::vector<uint8_t>& small = this->data_.size() <= other.data_.size() ? this->data_ : other.data_;
    std::vector<uint8_t> result(great.size(), 0);
    uint64_t i = 0;
    for (; i < small.size(); ++i)
    {
        result[i] = great[i] | small[i];
    }
    for (; i < great.size(); ++i)
    {
        result[i] = great[i];
    }
    return BinaryData(result);
}
NSROOT::BinaryData NSROOT::BinaryData::operator|(const BinaryData& other) const
{
    return this->bd_or(other);
}
NSROOT::BinaryData NSROOT::BinaryData::bd_xor(const BinaryData& other) const
{
    const std::vector<uint8_t>& great = this->data_.size() > other.data_.size() ? this->data_ : other.data_;
    const std::vector<uint8_t>& small = this->data_.size() <= other.data_.size() ? this->data_ : other.data_;
    std::vector<uint8_t> result(great.size(), 0);
    uint64_t i = 0;
    for (; i < small.size(); ++i)
    {
        result[i] = great[i] ^ small[i];
    }
    for (; i < great.size(); ++i)
    {
        result[i] = great[i];
    }
    return BinaryData(result);
}
NSROOT::BinaryData NSROOT::BinaryData::operator^(const BinaryData& other) const
{
    return this->bd_xor(other);
}
NSROOT::BinaryData NSROOT::BinaryData::bd_not() const
{
    std::vector<uint8_t> result(this->data_.size(), 0);
    std::transform(this->data_.begin(), this->data_.end(), result.begin(), [](uint8_t x) { return ~x; });
    return BinaryData(result);
}
NSROOT::BinaryData NSROOT::BinaryData::operator~() const
{
    return this->bd_not();
}

void NSROOT::BinaryData::bd_and_self(const BinaryData& other)
{
    const std::vector<uint8_t>& great = this->data_.size() > other.data_.size() ? this->data_ : other.data_;
    const std::vector<uint8_t>& small = this->data_.size() <= other.data_.size() ? this->data_ : other.data_;
    this->data_.resize(great.size(), 0);
    uint64_t i = 0;
    for (; i < small.size(); ++i)
    {
        this->data_[i] = great[i] & small[i];
    }
}
void NSROOT::BinaryData::operator&=(const BinaryData & other)
{
    this->bd_and_self(other);
}
void NSROOT::BinaryData::bd_or_self(const BinaryData & other)
{
    const std::vector<uint8_t>& great = this->data_.size() > other.data_.size() ? this->data_ : other.data_;
    const std::vector<uint8_t>& small = this->data_.size() <= other.data_.size() ? this->data_ : other.data_;
    this->data_.resize(great.size(), 0);
    uint64_t i = 0;
    for (; i < small.size(); ++i)
    {
        this->data_[i] = great[i] | small[i];
    }
    for (; i < great.size(); ++i)
    {
        this->data_[i] = great[i];
    }
}
void NSROOT::BinaryData::operator|=(const BinaryData & other)
{
    this->bd_or_self(other);
}
void NSROOT::BinaryData::bd_xor_self(const BinaryData & other)
{
    const std::vector<uint8_t>& great = this->data_.size() > other.data_.size() ? this->data_ : other.data_;
    const std::vector<uint8_t>& small = this->data_.size() <= other.data_.size() ? this->data_ : other.data_;
    this->data_.resize(great.size(), 0);
    uint64_t i = 0;
    for (; i < small.size(); ++i)
    {
        this->data_[i] = great[i] ^ small[i];
    }
    for (; i < great.size(); ++i)
    {
        this->data_[i] = great[i];
    }
}
void NSROOT::BinaryData::operator^=(const BinaryData & other)
{
    this->bd_xor_self(other);
}
void NSROOT::BinaryData::bd_not_self()
{
    std::transform(this->data_.begin(), this->data_.end(), this->data_.begin(), [](uint8_t x) { return ~x; });
}

NSROOT::BinaryData NSROOT::BinaryData::operator+(const BinaryData& other) const
{
    std::vector<uint8_t> result(this->data_.size() + other.data_.size(), 0);
    std::copy(this->data_.begin(), this->data_.end(), result.begin());
    std::copy(other.data_.begin(), other.data_.end(), result.begin() + this->data_.size());
    return BinaryData(result);
}
void NSROOT::BinaryData::operator+=(const BinaryData& other)
{
    uint64_t size = this->data_.size();
    this->data_.resize(this->data_.size() + other.data_.size(), 0);
    std::copy(other.data_.begin(), other.data_.end(), this->data_.begin() + size);
}

void NSROOT::BinaryData::operator+=(uint8_t elem)
{
    this->data_.push_back(elem);
}


#define NAMESPACE(name) dog_torch__serialize__##name
#define UTILS(name) dog_torch__utils__##name

NAMESPACE(BinaryData)* NAMESPACE(BinaryData_create_from_c_str)(LVALUE(UTILS(CppResultSet))result_set, const char* str, uint64_t type)
{
    try
    {
        return new NAMESPACE(BinaryData)(str, type);
    }
    catch (const std::exception& e)
    {
        dog_torch::utils::CppResultSet_reset(result_set, -1, e.what());
    }
    return nullptr;
}

NAMESPACE(BinaryData)* NAMESPACE(BinaryData_create_from_string)(LVALUE(UTILS(CppResultSet))result_set, const LVALUE(UTILS(CppString)) str, uint64_t type)
{
    try
    {
        return new NAMESPACE(BinaryData)(std::string_view(str->str_ptr, str->size), type);
    }
    catch (const std::exception& e)
    {
        dog_torch::utils::CppResultSet_reset(result_set, -1, e.what());
    }
    return nullptr;
}

void NAMESPACE(BinaryData_delete)(NAMESPACE(BinaryData)** self)
{
    DEFAULT_DESTOTY(self);
}

UTILS(CppString)* NAMESPACE(BinaryData_to_string)(const LVALUE(NAMESPACE(BinaryData)) self)
{
    return dog_torch::utils::to_c_style(self->to_string());
}

UTILS(CppString)* NAMESPACE(BinaryData_to_hex_string)(const LVALUE(NAMESPACE(BinaryData)) self, uint8_t is_upper)
{
    return dog_torch::utils::to_c_style(self->to_hex_string(is_upper));
}

UTILS(CppString)* NAMESPACE(BinaryData_to_base64_string)(const LVALUE(NAMESPACE(BinaryData)) self, char a, char b, char c)
{
    return dog_torch::utils::to_c_style(self->to_base64_string(a, b, c));
}

#undef NAMESPACE
#undef UTILS