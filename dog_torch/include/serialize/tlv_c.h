#pragma once

#include "tlv.h"

namespace dog_torch::serialize::tlv
{
	template<Type T, typename... Args>
	struct Param
	{
		static inline constexpr Type type;
		static bool check(const Value& v)
		{
			return true;
		}
	};

	template<>
	struct Param<Type::Null>
	{
		static inline constexpr Type type = Type::Null;
		static bool check(const Value& v)
		{
			return v.type() == Type::Null;
		}
	};

	template<>
	struct Param<Type::Bool, std::true_type>
	{
		static inline constexpr Type type = Type::Bool;
		static bool check(const Value& v)
		{
			return v.type() == Type::Bool && v.to_bool();
		}
	};

	template<>
	struct Param<Type::Bool, std::false_type>
	{
		static inline constexpr Type type = Type::Bool;
		static bool check(const Value& v)
		{
			return v.type() == Type::Bool && !v.to_bool();
		}
	};

	template<auto Callable>
		requires std::invocable<decltype(Callable), double>&& std::same_as<std::invoke_result_t<decltype(Callable), const Integer64&>, bool>
	struct Param<Type::Integer, dog_torch::utils::TpFuncation<Callable>>
	{
		static inline constexpr Type type = Type::Integer;
		static bool check(const Value& v)
		{
			if (v.type() != Type::Integer)
			{
				return false;
			}
			return dog_torch::utils::TpFuncation<Callable>::call(v.to_integer());
		}
	};

	template<auto Callable>
		requires std::invocable<decltype(Callable), double>&& std::same_as<std::invoke_result_t<decltype(Callable), double>, bool>
	struct Param<Type::Float, dog_torch::utils::TpFuncation<Callable>>
	{
		static inline constexpr Type type = Type::Float;
	};

	template<size_t N>
	struct Param<Type::Binary, dog_torch::utils::TpBinary<N>>
	{
		static inline constexpr Type type = Type::Binary;
		static inline const TpBinary<N>& binary;
		constexpr Param(const TpBinary<N>& b) : binary(b) {}
		static bool check(const Value& v)
		{
			if (v.type() != Type::Binary)
			{
				return false;
			}
			const auto& vb = v.to_binary();
			if (vb.size != N)
			{
				return false;
			}
			for (size_t i = 0; i < N; ++i)
			{
				if (vb.data[i] != binary.data[i])
				{
					return false;
				}
			}
			return true;
		}
	};

	template<auto Callable>
		requires std::invocable<decltype(Callable), double>&& std::same_as<std::invoke_result_t<decltype(Callable), const std::vector<uint8_t>&>, bool>
	struct Param<Type::Binary, dog_torch::utils::TpFuncation<Callable>>
	{
		static inline constexpr Type type = Type::Binary;
		static bool check(const Value& v)
		{
			if (v.type() != Type::Binary)
			{
				return false;
			}
			return dog_torch::utils::TpFuncation<Callable>::call(v.to_binary());
		}
	};

	template<size_t N>
	struct Param<Type::String, dog_torch::utils::TpU8String<N>>
	{
		static inline constexpr Type type = Type::String;
		static inline const TpU8String<N> string;
		constexpr Param(const TpU8String<N>& s) : string(s) {}
		static bool check(const Value& v)
		{
			if (v.type() != Type::String)
			{
				return false;
			}
			const auto& vs = v.to_string();
			if (vs.mib != 106)
			{
				return false;
			}
			for (size_t i = 0; i < N; ++i)
			{
				if (vs.data[i] != string.data[i])
				{
					return false;
				}
			}
			return true;
		}
	};

	template<uint64_t M, size_t N>
	struct Param<Type::String, dog_torch::utils::TpUnsignedInteger<M>, dog_torch::utils::TpString<N>>
	{
		static inline constexpr Type type = Type::String;
		static inline constexpr uint64_t mibs = M;
		static inline const TpString<N>& string;
		constexpr Param(dog_torch::utils::TpString<N> s) : string(s) {};
		static bool check(const Value& v)
		{
			if (v.type() != Type::String)
			{
				return false;
			}
			const auto& vs = v.to_string();
			if (vs.mib != mibs)
			{
				return false;
			}
			for (size_t i = 0; i < N; ++i)
			{
				if (vs.data[i] != string.data[i])
				{
					return false;
				}
			}
			return true;
		}
	};

	template<auto Callable>
		requires std::invocable<decltype(Callable), double>&& std::same_as<std::invoke_result_t<decltype(Callable), const MIBString&>, bool>
	struct Param<Type::String, dog_torch::utils::TpFuncation<Callable>>
	{
		static inline constexpr Type type = Type::String;
		static bool check(const Value& v)
		{
			if (v.type() != Type::String)
			{
				return false;
			}
			return dog_torch::utils::TpFuncation<Callable>::call(v.to_string());
		}
	};

	template<typename... Args>
	struct IsParam : std::false_type {};

	template<Type T, typename... Args>
	struct IsParam<Param<T, Args...>> : std::true_type {};

	template<typename T>
	concept is_param_c = IsParam<T>::value;

	namespace
	{
		template<size_t I,typename TUPLE>
		bool signle_check(const Value& v)
		{
			using T = std::remove_reference_t<std::remove_const_t<std::tuple_element_t<I, TUPLE>>>;
			return T::check(v);
		}
	}

	template<is_param_c... PARAMS>
	struct ArrayParams
	{
		static bool check(const std::vector<Value>& v)
		{
			constexpr size_t SIZE = sizeof...(PARAMS);
			using TUPLE = std::tuple<PARAMS...>;
			if (v.size() < SIZE)
			{
				return false;
			}
			return [&] <size_t... I> (std::index_sequence<I...>)
			{
				(
					signle_check<I, TUPLE>(v[i]) && ...
				)
			}(std::make_index_sequence<SIZE>{});
		};
	};

	template<is_param_c... PARAMS>
	struct Param<Type::Array, ArrayParams<PARAMS...>>
	{
		static inline constexpr Type type = Type::Array;
		static bool check(const Value& v)
		{
			if (v.type() != Type::Array)
			{
				return false;
			}
			return ArrayParams<PARAMS...>::check(v.to_array());
		}
	};

}