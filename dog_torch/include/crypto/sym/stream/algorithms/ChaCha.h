#pragma once
#include "export.h"

#include <array>
#include <iostream>
#include <functional>

#include "utils/compile.h"
#include "serialize/serialize.h"
#include "crypto/sym/sym_base.h"
#include "crypto/sym/stream/sym_stream_base.h"

namespace dog_torch::crypto::sym::stream::algorithm
{
    class ChaCha : public Algorithm
    {
    private:
        uint64_t count_ = 0;
    public:
        ChaCha(uint64_t round);

        static Config allowed_config();
        Config config() const override;
        std::unique_ptr<algorithm::Algorithm> clone() const override;

        static void inline trans(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
        static BinaryData generate_stream(const BinaryData& key_nonce, uint64_t count, uint64_t round);

        void init() override;
        uint64_t updata_size() const override;
        UpdateFunc update_func() override;
    };
}