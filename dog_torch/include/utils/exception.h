#pragma once
#ifdef SHARED
#include "export.h"
#else
#define DOG_TORCH_API
#endif
#include <exception>
#include <thread>
#include <array>
#include <string>
#include <format>

#ifdef STACKTRACE

#define DOG_TORCH_EXCEPTION_PARAMS \
	std::string_view msg,\
	std::basic_stacktrace<std::allocator<std::stacktrace_entry>> stacktrace,\
	std::thread::id thread_id,\
	std::string_view file,\
	std::string_view func,\
	uint64_t line

#define DOG_TORCH_EXCEPTION_OPINION\
	std::stacktrace::current(),\
	std::this_thread::get_id(),\
	(__FILE__),\
	(__func__),\
	(__LINE__)

#define DOG_TORCH_EXCEPTION_MSG(msg)\
	(msg),\
	DOG_TORCH_EXCEPTION_OPINION

#else


#define DOG_TORCH_EXCEPTION_PARAMS \
	std::string_view msg,\
	std::thread::id thread_id,\
	std::string_view file,\
	std::string_view func,\
	uint64_t line

#define DOG_TORCH_EXCEPTION_OPINION\
	std::this_thread::get_id(),\
	dog_torch::utils::Exception::get_abstract_path((__FILE__)),\
	(__func__),\
	(__LINE__)

#define DOG_TORCH_EXCEPTION_MSG(msg)\
	(msg), \
	DOG_TORCH_EXCEPTION_OPINION
	
#endif

#define DOG_EXCEPTION(msg) dog_torch::utils::Exception(DOG_TORCH_EXCEPTION_MSG(msg))

namespace dog_torch::utils
{

	class DOG_TORCH_API Exception : public std::exception
	{
	private:
		std::string msg_;
	public:
		Exception(DOG_TORCH_EXCEPTION_PARAMS);
		const char* what() const noexcept override;
		consteval static const char* get_abstract_path(const char* path)
		{
			std::string_view sv_path(path);
			constexpr std::string_view target = "dog_torch";

			size_t pos = sv_path.find(target);
			if (pos != std::string_view::npos)
			{
				return path + pos;
			}
			return nullptr;
		};
	};
}