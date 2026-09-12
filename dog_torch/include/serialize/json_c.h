#include "json.h"

namespace dog_torch::serialize::json
{
	template<Type T, typename... Args>
	struct Param
	{
		static inline constexpr Type type = Type::Undefined;
	};

	template<typename... Args>
	struct IsParam : std::false_type {};

	template<Type T, typename... Args>
	struct IsParam<Param<T, Args...>> : std::true_type {};

	template<typename T>
	concept is_param_c = IsParam<T>::value;

	template<>
	struct Param<Type::Null>
	{
		static inline constexpr Type type = Type::Null;
		static bool check(std::nullptr_t n)
		{
			return true;
		}
	};

	template<>
	struct Param<Type::Bool, std::true_type>
	{
		static inline constexpr Type type = Type::Bool;
		static bool check(bool b)
		{
			return b;
		}
	};

	template<>
	struct Param<Type::Bool, std::false_type>
	{
		static inline constexpr Type type = Type::Bool;
		static bool check(bool b)
		{
			return !b;
		}
	};

	template<auto Callable>
		requires std::invocable<decltype(Callable), double>&& std::same_as<std::invoke_result_t<decltype(Callable), double>, bool>
	struct Param<Type::Number, dog_torch::utils::TpFuncation<Callable>>
	{
		static inline constexpr Type type = Type::Number;
		static bool check(double v)
		{
			return dog_torch::utils::TpFuncation<Callable>::call(v);
		}
	};

	template<auto Callable>
		requires std::invocable<decltype(Callable), const std::string&>&& std::same_as<std::invoke_result_t<decltype(Callable), const std::string&>, bool>
	struct Param<Type::String, dog_torch::utils::TpFuncation<Callable>>
	{
		static inline constexpr Type type = Type::String;
		static bool check(const std::string& v)
		{
			return dog_torch::utils::TpFuncation<Callable>::call(v);
		}
	};

	namespace
	{
		template<typename TUPLE, size_t I>
		bool array_single_check(const Value& v)
		{
			using PARAM = std::remove_reference_t<std::remove_const_t<std::tuple_element_t<I, TUPLE>>>;
			return PARAM::check(v);
		}
	}

	template<is_param_c... PARAMS>
	struct ArrayParams
	{
		static bool check(const std::vector<Value>& v)
		{
			if (v.size() != sizeof...(PARAMS))
			{
				return false;
			}
			using TUPLE = std::tuple<PARAMS...>;
			return[&] <size_t... I>(std::index_sequence<I...>) -> bool
			{
				return (array_single_check<TUPLE, I>(v[I]) && ...);
			}(std::make_index_sequence<sizeof...(PARAMS)>{});
		}
	};


	template<is_param_c... PARAMS>
	struct Param<Type::Array, ArrayParams<PARAMS...>>
	{
		static inline constexpr Type type = Type::Array;
		static bool check(const std::vector<Value>& v)
		{
			return ArrayParams<PARAMS...>::check(v);
		}
	};

	template<dog_torch::utils::TpString NAME, is_param_c PARAM>
	struct ObjectParam
	{
		static inline dog_torch::utils::TpString name = NAME;
		static bool check(const Value& v)
		{
			return PARAM::check(v);
		}
	};

	namespace
	{
		template<typename TUPLE, size_t I>
		bool object_single_check(const std::unordered_map<std::string, Value>& v)
		{
			using PARAM = std::remove_reference_t<std::remove_const_t<std::tuple_element_t<I, TUPLE>>>;
			std::string key = PARAM::name.data.data();
			if (!v.contains(key))
			{
				return false;
			}
			return PARAM::check(v[key]);
		}

		template<typename... T>
		struct IsObjectParam : std::false_type {};
		template<dog_torch::utils::TpString NAME, is_param_c PARAM>
		struct IsObjectParam<ObjectParam<NAME, PARAM>> : std::true_type {};
		template<typename... T>
		concept is_ObjectParam_c = IsObjectParam<T...>::value;
	}

	template<is_ObjectParam_c... PARAMS>
	struct ObjectParams
	{
		static bool check(const std::unordered_map<std::string, Value>& v)
		{
			constexpr size_t SIZE = sizeof...(PARAMS);
			using TUPLE = std::tuple<PARAMS...>;
			return[&]<size_t... I>(std::index_sequence<I...>) -> bool
			{
				return (object_single_check<TUPLE, I>(v) && ...);
			}(std::make_index_sequence<SIZE>{});
		}
	};

	template<is_param_c... PARAMS>
	struct Param<Type::Object, ObjectParams<PARAMS...>>
	{
		static inline constexpr Type type = Type::Object;
		static bool check(const std::unordered_map<std::string, Value>& v)
		{
			return ObjectParams<PARAMS...>::check(v);
		}
	};

	template<is_param_c PARAM>
	bool check(const Value& v)
	{
		if (v.get_type() != PARAM::type)
		{
			return false;
		}
		if constexpr (PARAM::type == Type::Null)
		{
			return true;
		}
		else if constexpr (PARAM::type == Type::Bool)
		{
			return PARAM::check(v.to_bool());
		}
		else if constexpr (PARAM::type == Type::Number)
		{
			return PARAM::check(v.to_number());
		}
		else if constexpr (PARAM::type == Type::String)
		{
			return PARAM::check(v.to_string());
		}
		else if constexpr (PARAM::type == Type::Array)
		{
			return PARAM::check(v.to_array());
		}
		else if constexpr (PARAM::type == Type::Object)
		{
			return PARAM::check(v.to_object());
		}
		return false;
	}
}