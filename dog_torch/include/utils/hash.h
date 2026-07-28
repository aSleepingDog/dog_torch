#pragma once
#include "export.h"
#include <cstddef>
namespace dog_torch::utils::hash
{
	CPP_API size_t combine(size_t seed, size_t value);
}