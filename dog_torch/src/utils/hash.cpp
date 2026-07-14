#include "utils/hash.h"

namespace NSROOT = dog_torch::utils::hash;

size_t NSROOT::combine(size_t h1, size_t h2)
{
    h1 ^= h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2);
    return h1;
}

#undef NSROOT
