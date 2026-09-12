#pragma once
#include "napi_wrapper_utils.h"
#include "async\pool\pool.h"

using ResultString = dog_torch::async::pool::Result<std::string>;

Napi::Object registerThreadStatusEnum(Napi::Env env);
Napi::Object registerTaskTypeEnum(Napi::Env env);

class ThreadPoolWrapper : public Napi::ObjectWrap<ThreadPoolWrapper>, public dog_torch::napi::IWrapper
{
public:
    std::unique_ptr<dog_torch::async::pool::PausedThreadPool> self = nullptr;
    std::deque<ResultString> result;
    static inline Napi::FunctionReference constructor;

    ThreadPoolWrapper(const Napi::CallbackInfo& info);

    Napi::Value start(const Napi::CallbackInfo& info);

    Napi::Value wait(const Napi::CallbackInfo& info);

    Napi::Value stop_all(const Napi::CallbackInfo& info);

    Napi::Value pause_one(const Napi::CallbackInfo& info);

    Napi::Value resume_one(const Napi::CallbackInfo& info);

    Napi::Value cancel_one(const Napi::CallbackInfo& info);

    Napi::Value get_tasks_detail(const Napi::CallbackInfo& info);

    Napi::Value get_tasks_result(const Napi::CallbackInfo& info);

    Napi::Value add_hash_task(const Napi::CallbackInfo& info);

    Napi::Value add_encrypt_task(const Napi::CallbackInfo& info);

    Napi::Value add_decrypt_task(const Napi::CallbackInfo& info);

    static Napi::Object registerClass(Napi::Env env, Napi::Object exports);
};