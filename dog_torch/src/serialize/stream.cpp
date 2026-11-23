#include "serialize/stream.h"

namespace NSROOT = dog_torch::serialize::stream;

uint64_t NSROOT::read_bytes(const std::vector<uint8_t>& input, uint64_t total, uint64_t& now, std::vector<uint8_t>& buffer, uint64_t size, uint64_t& read_size)
{
    using dog_torch::utils::sub_bytes_len;
    using dog_torch::utils::sub_bytes_pos;
    if (total == 0 || size == 0) return 0;
    buffer.resize(size);
    buffer = now + size > total ? sub_bytes_pos(input, now, total) : sub_bytes_len(input,now, size);
    now += buffer.size();
    read_size = buffer.size();
    return buffer.size();
}
uint64_t NSROOT::read_bytes(std::istream& input, uint64_t total, uint64_t& now, std::vector<uint8_t>& buffer, uint64_t size, uint64_t& read_size)
{
    if (total == 0 || size == 0) return 0;
    if (total - now < size) size = total - now;
    buffer.resize(size);
    input.read(reinterpret_cast<char*>(buffer.data()), size);
    uint64_t read = input.gcount();
    buffer.resize(read);
    now += read;
    read_size = read;
    return read;
}

uint64_t NSROOT::read_bits(const std::vector<uint8_t>& input, uint64_t total, uint64_t& now, uint8_t& now_bit, std::vector<uint8_t>& buffer, uint64_t size, uint64_t& read_size)
{
    using dog_torch::utils::sub_bits_len;
    using dog_torch::utils::sub_bits_pos;
    if (total == 0 || size == 0) return 0;
    uint64_t now_bit_ = 0;
    if (now + size / 8 < total || (now + size / 8 == total && now_bit + size % 8 == 0))
    {
        buffer = sub_bits_len(input, now, now_bit, size);
        now_bit_ = now_bit + size;
    }
    else
    {
        buffer = sub_bits_pos(input, now, now_bit, total, 0);
        now_bit_ = (total - now) * 8 - now_bit;
    }
    if (now + now_bit_ / 8 >= total)
    {
        now_bit_ = (total - now) * 8 - now_bit;
        now = total;
        now_bit = 0;
        buffer.resize((now_bit_ + 7) / 8);
        read_size = now_bit_;
        return now_bit_;
    }
    now += now_bit_ / 8;
    now_bit = now_bit_ % 8;
    if (buffer.size() > (1 + ((size - 1) / 8)))
    {
        buffer.resize(1 + ((size - 1) / 8));
    }
    read_size = size;
    return size;
}
uint64_t NSROOT::read_bits(std::istream& input, uint64_t total, uint64_t& now, uint8_t& now_bit, std::vector<uint8_t>& buffer, uint64_t size, uint64_t& read_size)
{
    using dog_torch::utils::sub_bits_len;
    using dog_torch::utils::sub_bits_pos;
    using dog_torch::utils::bit_move_self;
    if (total == 0 || size == 0) return 0;
    uint64_t now_bit_ = now_bit + size;
    uint64_t len = now_bit_ / 8;
    buffer.resize(len + (now_bit_ % 8 > 0 ? 1 : 0));
    input.read(reinterpret_cast<char*>(buffer.data()), len);
    buffer.resize(len);
    if (now_bit_ % 8 > 0)
    {
        buffer.push_back(input.peek());
        buffer.back() &= (0xFF << (8 - now_bit_ % 8));
    }
    bit_move_self(buffer, false, false, now_bit);
    if (now + now_bit_ / 8 >= total)
    {
        now_bit_ = (total - now) * 8 - now_bit;
        now = total;
        now_bit = 0;
        buffer.resize((now_bit_ + 7) / 8);
        read_size = now_bit_;
        return now_bit_;
    }
    now += len;
    now_bit = now_bit_ % 8;
    if (buffer.size() > (1 + ((size - 1) / 8)))
    {
        buffer.resize(1 + ((size - 1) / 8));
    }
    read_size = size;
    return size;
}

void NSROOT::write_bits(std::vector<uint8_t>& output, uint8_t& buffer_byte, uint8_t& next_bit_set, uint64_t input_size, const std::vector<uint8_t>& buffer, uint64_t buffer_size)
{
    using dog_torch::utils::sub_bits_len;
    using dog_torch::utils::sub_bits_pos;
    using dog_torch::utils::bit_move;
    uint64_t effective_size = (buffer_size > input_size || input_size == 0) ? input_size : buffer_size;
    if (effective_size == 0) return;
    if (next_bit_set + effective_size > 7)
    {
        buffer_byte |= buffer[0] >> next_bit_set;
        output.push_back(buffer_byte);
        effective_size -= (8 - next_bit_set);
        std::vector<uint8_t> buffer_ = bit_move(buffer, false, false, (8 - next_bit_set));
        uint64_t end = output.size();
        output.resize(end + effective_size / 8);
        std::copy(buffer_.begin(), buffer_.begin() + effective_size / 8, output.begin() + end);
        if (!buffer_.size()) buffer_.push_back(0);
        buffer_byte = 0;
        buffer_byte |= buffer_[effective_size / 8] & (uint8_t(0xFF) << (8 - effective_size % 8));
        effective_size %= 8;
        next_bit_set = static_cast<uint8_t>(effective_size);
    }
    else
    {
        buffer_byte |= (buffer[0] >> (8 - effective_size)) << (8 - effective_size - next_bit_set);
        next_bit_set += static_cast<uint8_t>(effective_size);
    }
}
void NSROOT::write_bits(std::ostream& output, uint8_t& buffer_byte, uint8_t& next_bit_set, uint64_t input_size, const std::vector<uint8_t>& buffer, uint64_t buffer_size)
{
    using dog_torch::utils::sub_bits_len;
    using dog_torch::utils::sub_bits_pos;
    using dog_torch::utils::bit_move;
    uint64_t effective_size = (buffer_size > input_size || input_size == 0) ? input_size : buffer_size;
    if (effective_size == 0) return;
    if (next_bit_set + effective_size > 7)
    {
        buffer_byte |= buffer[0] >> next_bit_set;
        output.put(buffer_byte);
        effective_size -= (8 - next_bit_set);
        std::vector<uint8_t> buffer_ = bit_move(buffer, false, false, (8 - next_bit_set));
        output.write(reinterpret_cast<char*>(buffer_.data()), effective_size / 8);
        if (!buffer_.size()) buffer_.push_back(0);
        buffer_byte = 0;
        buffer_byte |= buffer_[effective_size / 8] & (uint8_t(0xFF) << (8 - effective_size % 8));
        effective_size %= 8;
        next_bit_set = static_cast<uint8_t>(effective_size);
    }
    else
    {
        buffer_byte |= (buffer[0] >> (8 - effective_size)) << (8 - effective_size - next_bit_set);
        next_bit_set += static_cast<uint8_t>(effective_size);
    }
}

