#pragma once
#include "napi.h"
#include <variant>
#include <optional>
#include <array>
#include <memory>

#include "math/math.h"

#define NOT_EMPTY(ptr) \
if(!(ptr)) throw Napi::Error::New(info.Env(),"Null pointer");

namespace dog_torch::napi
{

    struct IWrapper
    {
        virtual ~IWrapper() = default;
        virtual std::string __name() const;
    };

    template<typename T>
    concept NapiType = (
        std::is_same_v<T,Napi::Boolean> ||
        std::is_same_v<T,Napi::Number> ||
        std::is_same_v<T,Napi::String> ||
        std::is_same_v<T,Napi::Object> ||
        std::is_same_v<T,Napi::Array> ||
        std::is_same_v<T,Napi::BigInt> ||
        (std::is_base_of_v<Napi::ObjectWrap<T>, T> && std::is_base_of_v<IWrapper, T>));

    template<NapiType T>
    bool isType(const Napi::Value& value)
    {
        if constexpr (std::is_same_v<T,Napi::Boolean>)
        {
            return value.IsBoolean();
        }
        else if constexpr (std::is_same_v<T,Napi::Number>)
        {
            return value.IsNumber();
        }
        else if constexpr (std::is_same_v<T,Napi::String>)
        {
            return value.IsString();
        }
        else if constexpr (std::is_same_v<T,Napi::Array>)
        {
            return value.IsArray();
        }
        else if constexpr (std::is_same_v<T,Napi::Object>)
        {
            return value.IsObject();
        }
        else if constexpr (std::is_same_v<T,Napi::BigInt>)
        {
            return value.IsBigInt();
        }
        else if constexpr (std::is_base_of_v<Napi::ObjectWrap<T>, T>)
        {
            static_assert(typeid(T::__NAME)==typeid(std::string),"type must have __NAME static member");
            if (!value.IsObject()) return false;
            Napi::Object obj = value.As<Napi::Object>();
            IWrapper* p = static_cast<IWrapper*>(T::Unwrap(obj));
            return std::string(T::__NAME) == std::string(p->__name());
        }
    };

    template<typename T>
    requires std::is_enum_v<T>
    struct ArgValue
    {
        Napi::Value value;
        ArgValue() = default;
        ArgValue(const Napi::Value& value) : value(value) {};
    };

    template<typename T>
    requires std::is_same_v<T, Napi::Boolean>
    struct ArgValue<T>
    {
        bool value;
    };

    template<typename T>
    requires std::is_same_v<T, Napi::Number>
    struct ArgValue<T>
    {
        double value;

    };

    template<typename T>
    requires std::is_same_v<T, Napi::String>
    struct ArgValue<T>
    {
        std::string value;
    };

    template<typename T>
    requires std::is_base_of_v<Napi::ObjectWrap<T>, T>
    struct ArgValue<T>
    {
        T* value;
    };

    template<typename T>
    requires std::is_same_v<T, Napi::BigInt>
    struct ArgValue<T>
    {
        dog_torch::math::number::BigInteger value;
    };

    template<typename R,typename T,size_t I0>
    requires requires(R& r) { std::get<I0>(r).value; }
    void trans(R& result, const Napi::Value& value)
    {
        if (!isType<T>(value))
        {
            throw std::runtime_error("Invalid argument type");
        }
        if constexpr (std::is_same_v<T,Napi::Boolean>)
        {
            std::get<I0>(result).value = value.As<Napi::Boolean>().Value();
        }
        else if constexpr (std::is_same_v<T,Napi::Number>)
        {
            std::get<I0>(result).value = value.As<Napi::Number>().DoubleValue();
        }
        else if constexpr (std::is_same_v<T,Napi::String>)
        {
            std::get<I0>(result).value = value.As<Napi::String>().Utf8Value();
        }
        else if constexpr (std::is_base_of_v<Napi::ObjectWrap<T>, T>)
        {
            std::get<I0>(result).value = T::Unwrap(value.As<Napi::Object>());
        }
        else if constexpr (std::is_same_v<T,Napi::BigInt>)
        {
            using dog_torch::math::number::BigInteger;
            std::vector<uint64_t> vec(value.As<Napi::BigInt>().WordCount());
            if(vec.size()==0)
            {
                std::get<I0>(result).value = BigInteger{0,0};
            }
            else
            {
                int sign = 0;
                size_t len = value.As<Napi::BigInt>().WordCount();
                value.As<Napi::BigInt>().ToWords(
                    &sign,&len,vec.data()
                );
                std::get<I0>(result).value = BigInteger{sign,std::move(vec)};
            }
        }
        else
        {
            std::get<I0>(result).value = value;
        }
    };

    template<typename R,typename T,size_t I0>
    requires requires(R& r) { std::get<I0>(r).value; }
    bool trans_o(R& result, const Napi::Value& value)
    {
        if (!isType<T>(value))
        {
            return false;
        }
        if constexpr (std::is_same_v<T,Napi::Boolean>)
        {
            std::get<I0>(result).value = value.As<Napi::Boolean>().Value();
        }
        else if constexpr (std::is_same_v<T,Napi::Number>)
        {
            std::get<I0>(result).value = value.As<Napi::Number>().DoubleValue();
        }
        else if constexpr (std::is_same_v<T,Napi::String>)
        {
            std::get<I0>(result).value = value.As<Napi::String>().Utf8Value();
        }
        else if constexpr (std::is_base_of_v<Napi::ObjectWrap<T>, T>)
        {
            std::get<I0>(result).value = T::Unwrap(value.As<Napi::Object>());
        }
        else if constexpr (std::is_same_v<T,Napi::BigInt>)
        {
            using dog_torch::math::number::BigInteger;
            std::vector<uint64_t> vec(value.As<Napi::BigInt>().WordCount());
            if(vec.size()==0)
            {
                std::get<I0>(result).value = BigInteger{0,0};
            }
            else
            {
                int sign = 0;
                size_t len = value.As<Napi::BigInt>().WordCount();
                value.As<Napi::BigInt>().ToWords(
                    &sign,&len,vec.data()
                );
                std::get<I0>(result).value = BigInteger{sign,std::move(vec)};
            }
        }
        else
        {
            std::get<I0>(result).value = value;
        }
        return true;
    };

    template<NapiType... Args>
    std::tuple<ArgValue<Args>...> check_napi_args(const Napi::CallbackInfo& info)
    {
        constexpr uint64_t SIZE = sizeof...(Args);
        if (info.Length() != SIZE)
        {
            throw std::runtime_error("Invalid number of arguments");
        }
        using R = std::tuple<ArgValue<Args>...>;
        R result;
        [&]<size_t... I>(std::index_sequence<I...>)
        {
            (trans<R,
                std::remove_reference_t<std::remove_const_t<std::tuple_element_t<I,std::tuple<Args...>>>>,
                I>(result,info[I]),...);
        }( std::make_index_sequence<SIZE>{} );
        return result;
    };

    template<NapiType... Args>
    std::optional<std::tuple<ArgValue<Args>...>> check_napi_args_optional(const Napi::CallbackInfo& info)
    {
        constexpr uint64_t SIZE = sizeof...(Args);
        if (info.Length() != SIZE)
        {
            return std::nullopt;
        }
        using R = std::tuple<ArgValue<Args>...>;
        R result;

        bool r = [&]<size_t... I>(std::index_sequence<I...>)
            {
                if(!(trans_o<R,
                std::remove_reference_t<std::remove_const_t<std::tuple_element_t<I,std::tuple<Args...>>>>,
                I>(result,info[I])&&...))
                {
                    return false;
                }
                return true;
            }( std::make_index_sequence<SIZE>{} );
        if(!r)
        {
            return std::nullopt;
        }
        return result;
    };

    void throw_napi_error(const Napi::Env& env, const std::exception& e);
    void throw_napi_error(const Napi::Env& env, const std::string& e);
    
}
