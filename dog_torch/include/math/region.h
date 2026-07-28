#pragma once
#include "export.h"

#include <vector>
#include <string>

#include "utils/ctrans.h"
#include "utils/compile.h"
#include "utils/exception.h"

namespace dog_torch::math::region
{
	// X,X|X|X
	// [a,b|c]

	CPP_API uint64_t identify_integer(std::string_view::const_iterator& pos, const std::string_view::const_iterator& end);

	class CPP_API NumberIterator
	{
	private:
		bool is_list_ = false;
		std::vector<uint64_t> numbers_;
		uint64_t index_ = 0;
	public:
		NumberIterator(std::string_view str);

		NumberIterator(const NumberIterator& other);
		NumberIterator& operator=(const NumberIterator& other);
		NumberIterator(NumberIterator&& other) noexcept;
		NumberIterator& operator=(NumberIterator&& other) noexcept;

		bool have_next() const;
		uint64_t next();
	};

}

#define NAMESPACE(name) dog_torch__region__##name
#define UTILS(name) dog_torch__utils__##name

extern "C"
{
	using NAMESPACE(NumberIterator) = dog_torch::math::region::NumberIterator;
	C_API(NAMESPACE(NumberIterator)*) NAMESPACE(NumberIterator_create)      (LVALUE(UTILS(CppResultSet)) result_set, LVALUE(UTILS(CppString)) string);
	C_API(void)                       NAMESPACE(NumberIterator_delete)      (NAMESPACE(NumberIterator)** self);
	C_API(uint8_t)                    NAMESPACE(NumberIterator_have_next)   (const LVALUE(NAMESPACE(NumberIterator)) self);
	C_API(uint64_t)                   NAMESPACE(NumberIterator_next)        (LVALUE(NAMESPACE(NumberIterator)) self);
	C_API(UTILS(CppUint64Array)*)     NAMESPACE(NumberIterator_all_numbers) (LVALUE(NAMESPACE(NumberIterator)) self);
}

#undef NAMESPACE
#undef UTILS