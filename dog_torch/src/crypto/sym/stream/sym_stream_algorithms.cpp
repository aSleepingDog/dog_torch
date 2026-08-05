#include "crypto/sym/stream/sym_stream_algorithms.h"

namespace NSROOT = dog_torch::crypto::sym::stream::algorithm;

const std::vector<std::reference_wrapper<const NSROOT::Config>> NSROOT::get_all()
{
	return {
		std::cref(NSROOT::ChaCha::allowed_config())
	};
}

std::unique_ptr<NSROOT::Algorithm> NSROOT::create(const std::string& name, uint64_t effective, uint64_t key_size)
{
	if (name == NSROOT::ChaCha::allowed_config().name)
	{
		return std::make_unique<NSROOT::ChaCha>(effective);
	}
}
