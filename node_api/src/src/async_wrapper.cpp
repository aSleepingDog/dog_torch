#include "async_wrapper.h"
#include "crypto_hash_wrapper.h"
#include "crypto_sym_stream_wrapper.h"
#include "crypto_sym_block_wrapper.h"

Napi::Object registerThreadStatusEnum(Napi::Env env)
{
    Napi::Object threadStatus = Napi::Object::New(env);

    threadStatus["Created"] = Napi::Number::New(env, static_cast<int>(dog_torch::async::Status::Created));
    threadStatus["Ready"] = Napi::Number::New(env, static_cast<int>(dog_torch::async::Status::Ready));
    threadStatus["Running"] = Napi::Number::New(env, static_cast<int>(dog_torch::async::Status::Running));
    threadStatus["Blocked"] = Napi::Number::New(env, static_cast<int>(dog_torch::async::Status::Blocked));
    threadStatus["Stopped"] = Napi::Number::New(env, static_cast<int>(dog_torch::async::Status::Stopped));

    threadStatus[static_cast<int>(dog_torch::async::Status::Created)] = Napi::String::New(env, "Created");
    threadStatus[static_cast<int>(dog_torch::async::Status::Ready)] = Napi::String::New(env, "Ready");
    threadStatus[static_cast<int>(dog_torch::async::Status::Running)] = Napi::String::New(env, "Running");
    threadStatus[static_cast<int>(dog_torch::async::Status::Blocked)] = Napi::String::New(env, "Blocked");
    threadStatus[static_cast<int>(dog_torch::async::Status::Stopped)] = Napi::String::New(env, "Stopped");

    threadStatus.Freeze();
    return threadStatus;
}
Napi::Object registerTaskTypeEnum(Napi::Env env)
{
    Napi::Object taskType = Napi::Object::New(env);

    taskType["Hash"] = Napi::Number::New(env, 1);
    taskType["encrypt"] = Napi::Number::New(env, 2);
    taskType["decrypt"] = Napi::Number::New(env, 3);

    taskType[1] = Napi::String::New(env, "Hash");
    taskType[2] = Napi::String::New(env, "encrypt");
    taskType[3] = Napi::String::New(env, "decrypt");

    taskType.Freeze();
    return taskType;
}

ThreadPoolWrapper::ThreadPoolWrapper(const Napi::CallbackInfo& info)
: Napi::ObjectWrap<ThreadPoolWrapper>(info)
{
    this->self = std::make_unique<dog_torch::async::pool::PausedThreadPool>(4);
}
Napi::Value ThreadPoolWrapper::start(const Napi::CallbackInfo& info)
{
    try{
        NOT_EMPTY(this->self);
        this->self->start();
    }
    catch (const std::exception& e)
    {
        dog_torch::napi::throw_napi_error(info.Env(), e);
    }
    return info.Env().Undefined();
}
Napi::Value ThreadPoolWrapper::wait(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(this->self);
    this->self->wait_stop();
    return info.Env().Undefined();
}
Napi::Value ThreadPoolWrapper::stop_all(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(this->self);
    this->self->stop_all();
    this->self->wait_stop();
    return info.Env().Undefined();
}
Napi::Value ThreadPoolWrapper::pause_one(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(this->self);
    try
    {
        auto args = dog_torch::napi::check_napi_args<Napi::Number>(info);
        uint64_t task_id = static_cast<uint64_t>(std::get<0>(args).value);
        bool result = this->self->pause(task_id);
        return Napi::Boolean::New(info.Env(), result);
    }
    catch (const std::exception& e)
    {
        dog_torch::napi::throw_napi_error(info.Env(), e);
    }
    return info.Env().Undefined();
}
Napi::Value ThreadPoolWrapper::resume_one(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(this->self);
    try
    {
        auto args = dog_torch::napi::check_napi_args<Napi::Number>(info);
        uint64_t task_id = static_cast<uint64_t>(std::get<0>(args).value);
        bool result = this->self->resume(task_id);
        return Napi::Boolean::New(info.Env(), result);
    }
    catch (const std::exception& e)
    {
        dog_torch::napi::throw_napi_error(info.Env(), e);
    }
    return info.Env().Undefined();
}
Napi::Value ThreadPoolWrapper::cancel_one(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(this->self);
    try
    {
        auto args = dog_torch::napi::check_napi_args<Napi::Number>(info);
        uint64_t task_id = static_cast<uint64_t>(std::get<0>(args).value);
        bool result = this->self->cancel(task_id);
        if(result)
        {
            for(auto it = this->result.begin();it!=this->result.end();++it)
            {
                if((*it).task_id == task_id)
                {
                    this->result.erase(it);
                    break;
                }
            }
        }
        return Napi::Boolean::New(info.Env(), result);
    }
    catch (const std::exception& e)
    {
        dog_torch::napi::throw_napi_error(info.Env(), e);
    }
    return info.Env().Undefined();
}
Napi::Value ThreadPoolWrapper::get_tasks_detail(const Napi::CallbackInfo& info)
{
    auto fmt_iso_time = [](uint64_t milis_time)
    {
        using namespace dog_torch::async;
        auto r = convert<TimeUnit::Milliseconds, TimeUnit::Hours>(milis_time);
        std::string rs = "";
        //std::cout << r[0] << " " << r[1] << " " << r[2] << " " << r[3] << "\n";
        if (r[3] != 0)
        {
            rs += std::format("{:0>2}:", r[3]);
        }
        if (r[2] != 0)
        {
            rs += std::format("{:0>2}:", r[2]);
        }
        if (r[1] < 10)
        {
            rs += std::format("{}.", r[1]);
        }
        else
        {
            rs += std::format("{:0>2}.", r[1]);
        }
        rs += std::format("{:0>3}", r[0]);
        return rs;
    };
    NOT_EMPTY(this->self);
    try
    {
        auto details = this->self->get_tasks_detail();
        auto result = Napi::Array::New(info.Env(),details.size());
        for(uint64_t i = 0; i < details.size(); ++i)
        {
            const auto& detail = details[i];
            Napi::Object obj = Napi::Object::New(info.Env());
            obj.Set("taskId", Napi::Number::New(info.Env(), detail.task_id));
            obj.Set("status", Napi::Number::New(info.Env(), static_cast<int>(detail.status)));
            obj.Set("progress", Napi::Number::New(info.Env(), detail.progress));
            obj.Set("time", Napi::Number::New(info.Env(), detail.time));
            uint64_t elapsed = 0;
            if(detail.progress>0)
            {
                elapsed = static_cast<uint64_t>(detail.time * (1 / detail.progress - 1));
            }
            obj.Set("expected", Napi::String::New(info.Env(), fmt_iso_time(elapsed)));
            Napi::Object paramsObj = Napi::Object::New(info.Env());
            for(const auto& param : detail.params)
            {
                if(param.second.type() == typeid(uint64_t))
                {
                    paramsObj.Set(param.first, Napi::Number::New(info.Env(), std::any_cast<uint64_t>(param.second)));
                }
                else if(param.second.type() == typeid(std::string))
                {
                    paramsObj.Set(param.first, Napi::String::New(info.Env(), std::any_cast<std::string>(param.second)));
                }
                else
                {
                    paramsObj.Set(param.first, info.Env().Undefined());
                }
            }
            obj.Set("params", paramsObj);
            result.Set(i, obj);
        }
        return result;
    }
    catch (const std::exception& e)
    {
        dog_torch::napi::throw_napi_error(info.Env(), e);
    }
    return info.Env().Undefined();
}
Napi::Value ThreadPoolWrapper::get_tasks_result(const Napi::CallbackInfo& info)
{
    NOT_EMPTY(this->self);
    try{
        std::vector<std::pair<uint64_t,std::string>> result_vec;
        auto it = this->result.begin();
        while(it != this->result.end())
        {
            if((*it).future.wait_for(std::chrono::milliseconds(1))==std::future_status::ready)
            {
                result_vec.emplace_back((*it).task_id, (*it).future.get());
                it = this->result.erase(it);
            }
            else
            {
                ++it;
            }
        }
        Napi::Array result = Napi::Array::New(info.Env(), result_vec.size());
        for(uint64_t i=0;i<result_vec.size();i++)
        {
            Napi::Object obj = Napi::Object::New(info.Env());
            obj.Set("taskId", Napi::Number::New(info.Env(), result_vec[i].first));
            obj.Set("result", Napi::String::New(info.Env(), result_vec[i].second));            
            result.Set(i, obj);
        }
        return result;
    }
    catch (const std::exception& e)
    {
        dog_torch::napi::throw_napi_error(info.Env(), e);
    }
    return info.Env().Undefined();
}
Napi::Value ThreadPoolWrapper::add_hash_task(const Napi::CallbackInfo& info)
{
    using dog_torch::async::thread::PauseableChannel;
    using dog_torch::crypto::hash::Generator;
    NOT_EMPTY(this->self);
    try
    {
        auto args = dog_torch::napi::check_napi_args<
            HashGeneratorWrapper,
            Napi::String,
            BinaryParamsWrapper
        >(info);
        auto hash_generator = *std::get<0>(args).value->self.get();
        auto path_str = std::get<1>(args).value;
        auto params = std::get<2>(args).value;
        std::unordered_map<std::string, std::any> params_async = {
            {"type", static_cast<uint64_t>(0)},
            {"operator", hash_generator.fmt_string()},
            {"input", path_str},
            {"output", params->fmt_string()},
            {"timePoint", std::string(std::format("{:%Y-%m-%d %H:%M:%S}", std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now())))}
        };
        if(!std::filesystem::exists(path_str))
        {
            throw std::runtime_error("File does not exist: " + path_str);
        }
        auto task = [](PauseableChannel& pc,Generator gen, std::string path,BinaryParams params) -> std::string
        {
            uint64_t size = std::filesystem::file_size(path);
            std::ifstream file(path, std::ios::binary);
            auto hash = dog_torch::crypto::hash::Generator::calculate_with(pc,gen,file,size);
            return params.fmt_binary(hash);
        };
        auto task_con = this->self->add_task(params_async, task, hash_generator, path_str, params->toBinaryParams());
        uint64_t task_id = task_con.task_id;
        this->result.emplace_back(std::move(task_con));
        return Napi::Number::New(info.Env(), task_id);
    }
    catch (const std::exception& e)
    {
        dog_torch::napi::throw_napi_error(info.Env(), e);
    }
    return info.Env().Undefined();
}
Napi::Value ThreadPoolWrapper::add_encrypt_task(const Napi::CallbackInfo& info)
{
    using dog_torch::async::thread::PauseableChannel;
    using dog_torch::crypto::sym::block::BlockCipher;
    using dog_torch::crypto::sym::stream::StreamCipher;
    NOT_EMPTY(this->self);
    try
    {
        auto args0 = dog_torch::napi::check_napi_args_optional<
            BlockCipherWrapper,
            Napi::Boolean,
            Napi::String,
            Napi::String
        >(info);
        auto args1 = dog_torch::napi::check_napi_args_optional<
            StreamCipherWrapper,
            Napi::Boolean,
            Napi::String,
            Napi::String
        >(info);
        if(args0)
        {
            auto block_cipher = std::get<0>(args0.value()).value->self.get();
            auto with_header = std::get<1>(args0.value()).value;
            auto plain_path_str = std::get<2>(args0.value()).value;
            auto crypt_path_str = std::get<3>(args0.value()).value;
            if(!std::filesystem::exists(plain_path_str))
            {
                throw std::runtime_error("File does not exist: " + plain_path_str);
            }
            std::ofstream crypt_file(crypt_path_str, std::ios::binary);
            if(!crypt_file.is_open())
            {
                throw std::runtime_error("Failed to open crypt file: " + crypt_path_str);
            }
            std::shared_ptr<BlockCipher> shared_block_cipher = std::shared_ptr<BlockCipher>(static_cast<BlockCipher*>(block_cipher->clone().release()));
            std::unordered_map<std::string, std::any> params_async = {
                {"type", static_cast<uint64_t>(1)},
                {"operator", shared_block_cipher->fmt_string()},
                {"input", plain_path_str},
                {"output", crypt_path_str},
                {"timePoint", std::string(std::format("{:%Y-%m-%d %H:%M:%S}", std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now())))}
            };
            auto task = [](
                PauseableChannel& pc,
                std::shared_ptr<BlockCipher> cipher, bool with_head, std::string plain_path, std::string crypt_path)
            {
                try
                {
                    uint64_t size = std::filesystem::file_size(plain_path);
                    std::ifstream plain_file(plain_path, std::ios::binary);
                    cipher->init();
                    std::ofstream crypt_file(crypt_path, std::ios::binary);
                    auto header = cipher->serialize().serialize();
                    crypt_file.write(reinterpret_cast<const char*>(header.data()), header.size());
                    cipher->encryptp_stream(pc,plain_file,size,crypt_file);
                    return std::string("success");
                }
                catch (const std::exception& e)
                {
                    return std::string(e.what());
                }
            };
            auto task_con = this->self->add_task(params_async, task,
                shared_block_cipher, with_header,
                plain_path_str, crypt_path_str);
            uint64_t task_id = task_con.task_id;
            this->result.emplace_back(std::move(task_con));
            return Napi::Number::New(info.Env(), task_id);
        }
        else if(args1)
        {
            auto stream_cipher = std::get<0>(args1.value()).value->self.get();
            auto with_header = std::get<1>(args1.value()).value;
            auto plain_path_str = std::get<2>(args1.value()).value;
            auto crypt_path_str = std::get<3>(args1.value()).value;
            if(!std::filesystem::exists(plain_path_str))
            {
                throw std::runtime_error("File does not exist: " + plain_path_str);
            }
            std::ofstream crypt_file(crypt_path_str, std::ios::binary);
            if(!crypt_file.is_open())
            {
                throw std::runtime_error("Failed to open crypt file: " + crypt_path_str);
            }
            std::shared_ptr<StreamCipher> shared_stream_cipher = std::shared_ptr<StreamCipher>(static_cast<StreamCipher*>(stream_cipher->clone().release()));
            std::unordered_map<std::string, std::any> params_async = {
                {"type", static_cast<uint64_t>(1)},
                {"operator", shared_stream_cipher->fmt_string()},
                {"input", plain_path_str},
                {"output", crypt_path_str},
                {"timePoint", std::string(std::format("{:%Y-%m-%d %H:%M:%S}", std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now())))}
            };
            auto task = [](
                PauseableChannel& pc,
                std::shared_ptr<StreamCipher> cipher, bool with_head, std::string plain_path, std::string crypt_path)
            {
                try
                {
                    uint64_t size = std::filesystem::file_size(plain_path);
                    std::ifstream plain_file(plain_path, std::ios::binary);
                    cipher->init();
                    std::ofstream crypt_file(crypt_path, std::ios::binary);
                    auto header = cipher->serialize().serialize();
                    crypt_file.write(reinterpret_cast<const char*>(header.data()), header.size());
                    cipher->encryptp_stream(pc,plain_file,size,crypt_file);
                    return std::string("success");
                }
                catch (const std::exception& e)
                {
                    return std::string(e.what());
                }

            };
            auto task_con = this->self->add_task(params_async, task,
                shared_stream_cipher, with_header,
                plain_path_str, crypt_path_str);
            uint64_t task_id = task_con.task_id;
            this->result.emplace_back(std::move(task_con));
            return Napi::Number::New(info.Env(), task_id);
        }
        else
        {
            throw std::runtime_error("Invalid arguments for add_encrypt_task.");
        }
    }
    catch (const std::exception& e)
    {
        dog_torch::napi::throw_napi_error(info.Env(), e);
    }
    return info.Env().Undefined();
}
std::pair<uint64_t,std::unique_ptr<dog_torch::crypto::sym::Cipher>> parse(std::ifstream& input)
{
    using dog_torch::serialize::tlv::Value;
    using dog_torch::crypto::Param;
    auto p = [](Value value) -> std::unique_ptr<dog_torch::crypto::sym::Cipher>
    {
        namespace tlv = dog_torch::serialize::tlv;        using dog_torch::crypto::Param;
        const auto& root_obj = value.to_object();
        if (root_obj.size() != 1 && !root_obj.contains(tlv::MIBString{ "Block" }) && !root_obj.contains(tlv::MIBString{ "Stream" }))
        {
            throw std::runtime_error("head not found");
        }
        else if(root_obj.contains(tlv::MIBString{ "Block" }))
        {
            const auto& cipher_config = root_obj.at(tlv::MIBString{ "Block" }).to_array();
            const auto& algorithm_configs = cipher_config.at(0).to_array();
            std::string alg_name = algorithm_configs.at(0).to_string().string;
            uint64_t block_size = algorithm_configs.at(1).to_integer().number;
            uint64_t key_size = algorithm_configs.at(2).to_integer().number;
            auto alg_ptr = dog_torch::crypto::sym::block::algorithm::create(alg_name, block_size, key_size);
            if (alg_ptr == nullptr)
            {
                throw std::runtime_error("algorithm not support");
            }
            const auto& mode_configs = cipher_config.at(1).to_array();
            std::string mode_name = mode_configs.at(0).to_string().string;
            std::string paddding_name = mode_configs.at(1).to_string().string;
            auto padding = dog_torch::crypto::sym::block::padding::create(paddding_name);
            if (padding == nullptr)
            {
                throw std::runtime_error("padding not support");
            }
            std::unordered_map<std::string, Param> tar_params;
            if (mode_configs.size() > 2)
            {
                const auto& mode_args = mode_configs.at(2).to_object();
                for (const auto& [key, value] : mode_args)
                {
                    std::string key_name = key.string;
                    if (value.type() == tlv::Type::Bool)
                    {
                        tar_params[key_name] = value.to_bool();
                    }
                    else if (value.type() == tlv::Type::Integer)
                    {
                        tar_params[key_name] = value.to_integer().number;
                    }
                    else if (value.type() == tlv::Type::String)
                    {
                        tar_params[key_name] = value.to_string().string;
                    }
                    else if (value.type() == tlv::Type::Binary)
                    {
                        tar_params[key_name] = value.to_binary();
                    }
                }
            }
            auto mode = dog_torch::crypto::sym::block::mode::create(mode_name, *padding, tar_params);
            if (mode == nullptr)
            {
                throw std::runtime_error("mode not support");
            }
            return std::make_unique<dog_torch::crypto::sym::block::BlockCipher>(*alg_ptr, *mode);
        }
        else if(root_obj.contains(tlv::MIBString{ "Stream" }))
        {
            const auto& cipher_config = root_obj.at(tlv::MIBString{ "Stream" }).to_array();
            const auto& alg_p = cipher_config.at(0).to_array();
            std::string alg_name = alg_p.at(0).to_string().string;
            uint64_t effi_size = alg_p.at(1).to_integer().number;
            uint64_t key_size = alg_p.at(2).to_integer().number;
            const auto& silce = cipher_config.at(1).to_array();
            bool is_bit = silce.at(0).to_bool();
            uint64_t shift = silce.at(1).to_integer().number;
            auto alg_ptr = dog_torch::crypto::sym::stream::algorithm::create(alg_name, effi_size, key_size);
            if (alg_ptr == nullptr)
            {
                throw std::runtime_error("algorithm not support");
            }
            return std::make_unique<dog_torch::crypto::sym::stream::StreamCipher>(*alg_ptr,shift,is_bit);
        }
        return nullptr;
    };
    Value value = Value::parse(input);
    uint64_t head_size = input.tellg();
    return { head_size, p(value) };
}
Napi::Value ThreadPoolWrapper::add_decrypt_task(const Napi::CallbackInfo& info)
{
    using dog_torch::async::thread::PauseableChannel;
    using dog_torch::crypto::sym::block::BlockCipher;
    using dog_torch::crypto::sym::stream::StreamCipher;
    NOT_EMPTY(this->self);
    try
    {
        auto args0 = dog_torch::napi::check_napi_args_optional<
            BlockCipherWrapper,
            Napi::String,
            Napi::String
        >(info);
        auto args1 = dog_torch::napi::check_napi_args_optional<
            StreamCipherWrapper,
            Napi::String,
            Napi::String
        >(info);
        auto args2 = dog_torch::napi::check_napi_args_optional<
            BinaryDataWrapper,
            Napi::String,
            Napi::String
        >(info);
        if(args0)
        {
            using dog_torch::crypto::sym::block::BlockCipher;
            auto cipher = std::make_shared<BlockCipher>(std::move(*std::get<0>(*args0).value->self.release()));
            auto crypt_path = std::get<1>(*args0).value;
            auto plain_path = std::get<2>(*args0).value;
            if(!std::ifstream{crypt_path}.good())
            {
                throw std::runtime_error("crypt can not read");
            }
            if(!std::ofstream{plain_path}.good())
            {
                throw std::runtime_error("plain can not write");
            }
            std::unordered_map<std::string, std::any> params_async = {
                {"type", static_cast<uint64_t>(2)},
                {"operator", cipher->fmt_string()},
                {"input", crypt_path},
                {"output", plain_path},
                {"timePoint", std::string(std::format("{:%Y-%m-%d %H:%M:%S}", std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now())))}
            };
            auto task = [](PauseableChannel& pc, std::shared_ptr<BlockCipher> cipher, std::string crypt_path, std::string plain_path)
            {
                try
                {
                    uint64_t size = std::filesystem::file_size(crypt_path);
                    std::ifstream crypt{crypt_path, std::ios::binary};
                    std::ofstream plain{plain_path, std::ios::binary};
                    cipher->init();
                    cipher->decryptp_stream(pc,crypt,size,plain);
                    return std::string("success");
                }
                catch (const std::exception& e)
                {
                    return std::string(e.what());
                }
            };
            auto task_con = this->self->add_task(
                params_async,task, cipher, crypt_path, plain_path
            );
            uint64_t task_id = task_con.task_id;
            this->result.emplace_back(std::move(task_con));
            return Napi::Number::New(info.Env(), task_id);
        }
        else if(args1)
        {
            using dog_torch::crypto::sym::stream::StreamCipher;
            auto cipher = std::make_shared<StreamCipher>(std::move(*std::get<0>(*args1).value->self.release()));
            auto crypt_path = std::get<1>(*args1).value;
            auto plain_path = std::get<2>(*args1).value;
            if(!std::ifstream{crypt_path}.good())
            {
                throw std::runtime_error("crypt can not read");
            }
            if(!std::ofstream{plain_path}.good())
            {
                throw std::runtime_error("plain can not write");
            }
            std::unordered_map<std::string, std::any> params_async = {
                {"type", static_cast<uint64_t>(2)},
                {"operator", cipher->fmt_string()},
                {"input", crypt_path},
                {"output", plain_path},
                {"timePoint", std::string(std::format("{:%Y-%m-%d %H:%M:%S}", std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now())))}
            };
            auto task = [](PauseableChannel& pc, std::shared_ptr<StreamCipher> cipher, std::string crypt_path, std::string plain_path)
            {
                try
                {
                    uint64_t size = std::filesystem::file_size(crypt_path);
                    std::ifstream crypt{crypt_path, std::ios::binary};
                    std::ofstream plain{plain_path, std::ios::binary};
                    cipher->init();
                    cipher->decryptp_stream(pc,crypt,size,plain);
                    return std::string("success");
                }
                catch (const std::exception& e)
                {
                    return std::string(e.what());
                }
            };
            auto task_con = this->self->add_task(
                params_async,task, cipher, crypt_path, plain_path
            );
            uint64_t task_id = task_con.task_id;
            this->result.emplace_back(std::move(task_con));
            return Napi::Number::New(info.Env(), task_id);
        }
        else if(args2)
        {
            auto key = std::get<0>(*args2).value->data();
            auto crypt_path = std::get<1>(*args2).value;
            auto plain_path = std::get<2>(*args2).value;
            if(!std::ifstream{crypt_path}.good())
            {
                throw std::runtime_error("crypt can not read");
            }
            if(!std::ofstream{plain_path}.good())
            {
                throw std::runtime_error("plain can not write");
            }
            std::unordered_map<std::string, std::any> params_async = {
                {"type", static_cast<uint64_t>(2)},
                {"operator", "parse..."},
                {"input", crypt_path},
                {"output", plain_path},
                {"timePoint", std::string(std::format("{:%Y-%m-%d %H:%M:%S}", std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now())))}
            };
            auto task = [](PauseableChannel& pc, BinaryData key, std::string crypt_path, std::string plain_path)
            {
                try
                {
                    uint64_t total = std::filesystem::file_size(crypt_path);
                    std::ifstream crypt{crypt_path, std::ios::binary};
                    auto [size,cipher] = parse(crypt);
                    cipher->set_key(key);
                    cipher->init();
                    std::ofstream plain{plain_path, std::ios::binary};
                    pc.param("operator") = std::string(cipher->fmt_string());
                    cipher->decryptp_stream(pc,crypt,total-size,plain);
                    return std::string("success");
                }
                catch (const std::exception& e)
                {
                    return std::string(e.what());
                }
            };
            auto task_con = this->self->add_task(
                params_async,task, key, crypt_path, plain_path
            );
            uint64_t task_id = task_con.task_id;
            this->result.emplace_back(std::move(task_con));
            return Napi::Number::New(info.Env(), task_id);
        }
        else
        {
            throw std::runtime_error("Invalid arguments for add_decrypt_task.");
        }
    }
    catch (const std::exception& e)
    {
        dog_torch::napi::throw_napi_error(info.Env(), e);
    }
    return info.Env().Undefined();
}
Napi::Object ThreadPoolWrapper::registerClass(Napi::Env env, Napi::Object exports)
{
    Napi::HandleScope scope(env);
    Napi::Function func = DefineClass(env, "ThreadPool", {
        InstanceMethod("start", &ThreadPoolWrapper::start),
        InstanceMethod("wait", &ThreadPoolWrapper::wait),
        InstanceMethod("stopAll", &ThreadPoolWrapper::stop_all),
        InstanceMethod("pause", &ThreadPoolWrapper::pause_one),
        InstanceMethod("resume", &ThreadPoolWrapper::resume_one),
        InstanceMethod("cancel", &ThreadPoolWrapper::cancel_one),
        InstanceMethod("taskDetails", &ThreadPoolWrapper::get_tasks_detail),
        InstanceMethod("taskResults", &ThreadPoolWrapper::get_tasks_result),
        InstanceMethod("addHashTask", &ThreadPoolWrapper::add_hash_task),
        InstanceMethod("addEncryptTask", &ThreadPoolWrapper::add_encrypt_task),
        InstanceMethod("addDecryptTask", &ThreadPoolWrapper::add_decrypt_task),
    });
    ThreadPoolWrapper::constructor = Napi::Persistent(func);
    ThreadPoolWrapper::constructor.SuppressDestruct();
    exports.Set("ThreadPool", func);
    return exports;
}