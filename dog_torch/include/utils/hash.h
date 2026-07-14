#pragma once
#include "export.h"

namespace dog_torch::utils::hash
{
	DOG_TORCH_API size_t combine(size_t seed, size_t value);
}