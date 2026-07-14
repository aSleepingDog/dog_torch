#include "utils/ctrans.h"

namespace NSROOT = dog_torch::utils;
#define NAMESPACE(name) dog_torch__utils__##name

NAMESPACE(CppString)* NSROOT::to_c_style(const std::string& cppstr)
{
	NAMESPACE(CppString)* result = new NAMESPACE(CppString)();
	if (result != nullptr)
	{
		result->size = cppstr.size();
		result->str_ptr = new char[result->size + 1];
		memcpy(result->str_ptr, cppstr.c_str(), result->size);
		result->str_ptr[result->size] = '\0';
	}
	return result;
}
std::string NSROOT::to_string(const LVALUE(NAMESPACE(CppString))cstr)
{
	if (cstr == nullptr) throw DOG_EXCEPTION("Null pointer");
	return std::string(cstr->str_ptr, cstr->size);
}

NAMESPACE(CppUint64Array)* NSROOT::to_c_style(const std::vector<uint64_t>& cppvec)
{
	NAMESPACE(CppUint64Array)* result = new NAMESPACE(CppUint64Array)();
	if (result != nullptr)
	{
		result->size = cppvec.size();
		result->data = new uint64_t[result->size];
		for (uint64_t i = 0; i < result->size; i++)
		{
			result->data[i] = cppvec[i];
		}
	}
	return result;
}

void NSROOT::CppResultSet_reset(LVALUE(NAMESPACE(CppResultSet))self, int64_t code, const std::string& msg)
{
	if (self == nullptr) return;
	self->code = code;
	if (self->msg != nullptr)
	{
		NAMESPACE(CppString_delete)(&self->msg);
		self->msg = to_c_style(msg);
	}
}

const char* NAMESPACE(CppString_get_c_str)(const LVALUE(NAMESPACE(CppString)) target)
{
	return target->str_ptr;
}

void NAMESPACE(CppString_delete)(NAMESPACE(CppString)** target)
{
	if (*target != nullptr)
	{
		delete[] (*target)->str_ptr;
		delete *target;
	}
	*target = nullptr;
}

NAMESPACE(CppResultSet)* NAMESPACE(CppResultSet_create)()
{
	auto result = new NAMESPACE(CppResultSet)();
	result->code = 0;
	result->msg = nullptr;
	return result;
}

void NAMESPACE(CppResultSet_delete)(NAMESPACE(CppResultSet)** self)
{
	if (*self == nullptr) return;
	if ((*self)->msg != nullptr) NAMESPACE(CppString_delete)(&((*self)->msg));
	delete self;
	self = nullptr;
}

const char* NAMESPACE(CppResultSet_get_msg)(const LVALUE(NAMESPACE(CppResultSet)) self)
{
	if (self == nullptr) return nullptr;
	return self->msg != nullptr ? self->msg->str_ptr : nullptr;
}

int64_t NAMESPACE(CppResultSet_get_code)(const LVALUE(NAMESPACE(CppResultSet)) self)
{
	if (self == nullptr) return 0;
	return self->code;
}

uint64_t NAMESPACE(CppUint64Array_at)(LVALUE(NAMESPACE(CppResultSet)) result, const LVALUE(NAMESPACE(CppUint64Array))target, uint64_t index)
{
	using NSROOT::CppResultSet_reset;
	if (target == nullptr)
	{
		CppResultSet_reset(result, -1, "Null pointer");
	}
	if (index >= target->size)
	{
		CppResultSet_reset(result, -2, "Index out of range");
	}
	return target->data[index];
}

void NAMESPACE(CppUint64Array_delete)(NAMESPACE(CppUint64Array)** target)
{
	if (*target == nullptr) return;
	delete[](*target)->data;
	delete *target;
	*target = nullptr;
}

#undef NAMESPACE
