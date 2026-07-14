#include "crypto/mac/hmac_base.h"

namespace NSROOT = dog_torch::crypto::mac;

NSROOT::HMacGenerator::HMacGenerator(const BinaryData& key, const hash_algorithm_uptr& hash_algorithm) : MacGenerator(key), hash_algorithm_(hash_algorithm->clone())
{}
NSROOT::HMacGenerator::HMacGenerator(const BinaryData & key, hash_algorithm_uptr&& hash_algorithm) noexcept : MacGenerator(key), hash_algorithm_(std::move(hash_algorithm))
{}

NSROOT::HMacGenerator::~HMacGenerator() = default;

NSROOT::BinaryData NSROOT::HMacGenerator::generate(const BinaryData& data)
{
    using HashGenerator = dog_torch::crypto::hash::Generator;
    BinaryData effective_key = this->key_;
    uint64_t block_size = this->hash_algorithm_->get_block_size();
    HashGenerator hasher(this->hash_algorithm_);
    if (key_.size() > block_size) effective_key = hasher.calculate(key_);
    while (effective_key.size() < block_size) effective_key.push_back(0x00);
    BinaryData ipad; ipad.reserve(block_size);
    BinaryData opad; opad.reserve(block_size);
    for (uint64_t i = 0; i < block_size; i++)
    {
        ipad.push_back(effective_key[i] ^ 0x36);
        opad.push_back(effective_key[i] ^ 0x5C);
    }
    auto update_func = this->hash_algorithm_->get_update();
    auto trims_func = this->hash_algorithm_->get_trims();
    hash_algorithm_->init();
    BinaryData value = this->hash_algorithm_->init_data();
    update_func(ipad, value);
    uint64_t pos = block_size;
    do
    {
        BinaryData block = this->hash_algorithm_->next_block(data, pos - block_size, pos, data.size() + block_size);
        update_func(block, value);
    } while (this->hash_algorithm_->have_next_block(pos, data.size() + block_size));
    trims_func(value);
    opad += value;
    return hasher.calculate(opad);
}
NSROOT::HMacGenerator::hash_algorithm_t& NSROOT::HMacGenerator::get_hash_algorithm()
{
    return *this->hash_algorithm_;
}
NSROOT::BinaryData NSROOT::HMacGenerator::generate(std::istream& input, uint64_t total)
{
    using HashGenerator = dog_torch::crypto::hash::Generator;
    BinaryData effective_key = this->key_;
    uint64_t block_size = this->hash_algorithm_->get_block_size();
    HashGenerator hasher(this->hash_algorithm_);
    if (key_.size() > block_size) effective_key = hasher.calculate(key_);
    while (effective_key.size() < block_size) effective_key.push_back(0x00);
    BinaryData ipad; ipad.reserve(block_size);
    BinaryData opad; opad.reserve(block_size);
    for (uint64_t i = 0; i < block_size; i++)
    {
        ipad.push_back(effective_key[i] ^ 0x36);
        opad.push_back(effective_key[i] ^ 0x5C);
    }
    auto update_func = this->hash_algorithm_->get_update();
    auto trims_func = this->hash_algorithm_->get_trims();
    hash_algorithm_->init();
    BinaryData value = this->hash_algorithm_->init_data();
    update_func(ipad, value);
    uint64_t pos = block_size;
    do
    {
        BinaryData block = this->hash_algorithm_->next_block(input, pos, total + block_size);
        update_func(block, value);
    } while (this->hash_algorithm_->have_next_block(pos, total + block_size));
    trims_func(value);
    opad += value;
    return hasher.calculate(opad);
}

NSROOT::BinaryData NSROOT::HMacGenerator::generate(PauseableChannel& pc, std::istream& input, uint64_t total)
{
    using HashGenerator = dog_torch::crypto::hash::Generator;
    pc.start();
    BinaryData effective_key = this->key_;
    uint64_t block_size = this->hash_algorithm_->get_block_size();
    HashGenerator hasher(this->hash_algorithm_);
    if (key_.size() > block_size) effective_key = hasher.calculate(key_);
    while (effective_key.size() < block_size) effective_key.push_back(0x00);
    BinaryData ipad; ipad.reserve(block_size);
    BinaryData opad; opad.reserve(block_size);
    for (uint64_t i = 0; i < block_size; i++)
    {
        ipad.push_back(effective_key[i] ^ 0x36);
        opad.push_back(effective_key[i] ^ 0x5C);
    }
    auto update_func = this->hash_algorithm_->get_update();
    auto trims_func = this->hash_algorithm_->get_trims();
    hash_algorithm_->init();
    BinaryData value = this->hash_algorithm_->init_data();
    update_func(ipad, value);
    uint64_t pos = block_size;
    pc.add_progress(block_size * 1.0 / total);
    do
    {
        if (pc.check_status()) break;
        BinaryData block = this->hash_algorithm_->next_block(input, pos, total + block_size);
        update_func(block, value);
        pc.add_progress(block_size * 1.0 / total);
    } while (this->hash_algorithm_->have_next_block(pos, total + block_size));
    trims_func(value);
    opad += value;
    opad = hasher.calculate(opad);
    pc.set_progress(1.0);
    pc.stop();
    return opad;
}

std::string NSROOT::HMacGenerator::fmt_string() const
{
    return std::format("HMAC<{}>", this->hash_algorithm_->fmt_string());
}

#undef NSROOT