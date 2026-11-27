#pragma once
#include "export.h"

#include <exception>
#include <cstdint>
#include <cstring>

namespace dog_torch::math::random
{
    CPP_API uint64_t random_uint64() noexcept;
    CPP_API void random_block(char* s, uint64_t len) noexcept;
}