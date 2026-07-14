#include "crypto/mac/mac_base.h"

namespace NSROOT = dog_torch::crypto::mac;

NSROOT::MacGenerator::MacGenerator(const BinaryData& key) : key_(key) {}
NSROOT::MacGenerator::~MacGenerator() {}
NSROOT::BinaryData NSROOT::MacGenerator::generate(const BinaryData& data)
{
    return data ^ key_;
}
std::string NSROOT::MacGenerator::fmt() const
{
    return std::string();
}
NSROOT::BinaryData dog_torch::crypto::mac::MacGenerator::key() const
{
    return this->key_;
}
void dog_torch::crypto::mac::MacGenerator::set_key(const BinaryData& new_key)
{
    this->key_ = new_key;
}
NSROOT::BinaryData NSROOT::MacGenerator::generate(std::istream& input, uint64_t total)
{
    BinaryData data(total);
    input.read((char*)(data.data_ptr()), total);
    return data ^ key_;
}

NSROOT::BinaryData dog_torch::crypto::mac::MacGenerator::generate(PauseableChannel& pc, std::istream& input, uint64_t total)
{
    pc.start();
    BinaryData data(total);
    input.read((char*)(data.data_ptr()), total);
    return data ^ key_;
    pc.stop();
}

std::string NSROOT::MacGenerator::fmt_string() const
{
    return "MAC";
}

#undef NSROOT