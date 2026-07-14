#include "utils/exception.h"

namespace NSROOT = dog_torch::utils;

NSROOT::Exception::Exception(DOG_TORCH_EXCEPTION_PARAMS)
{
	this->msg_ += std::format("{}\n[{}]\"{}\":{}->{}\n", msg, thread_id, file, line, func);
#ifdef STACKTRACE
	for (auto& stack : stacktrace)
	{
		this->msg += std::format("|--\"{}\":{}->{}\n", stack.source_file(), stack.source_line(), stack.description());
	}
#endif
}

const char* NSROOT::Exception::what() const noexcept
{
	return this->msg_.c_str();
}

#undef NSROOT
