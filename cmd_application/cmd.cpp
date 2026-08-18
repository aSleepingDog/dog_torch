#include <iostream>
#include <thread>
#include <string>
#include <vector>
#include <optional>
#include <variant>
#include <filesystem>
#include <format>

#include "async/pool/pool.h"
#include "serialize/serialize.h"

#include "crypto/hash/hash_algorithms.h"
#include "crypto/sym/block/sym_block_algorithms.h"
#include "crypto/sym/block/sym_block_paddings.h"
#include "crypto/sym/block/sym_block_modes.h"

void enableVirtualTerminal();
void clear_cmd();
void pause_cmd();

namespace dog_torch::serialize
{
	enum class Type : uint64_t
	{
		UTF_8 = 0,
		Binary = 1,
		Hex = 2,
		Base64 = 3,
	};

	std::string type_fmt_string(Type type);

	class BinaryParams
	{
		using Param = std::variant<bool, char>;
	private:
		Type type_;
		std::vector<Param> params_;
	public:
		BinaryParams() = default;

		static BinaryParams from_utf8();
		static BinaryParams from_binary();
		static BinaryParams from_hex(bool is_upper);
		static BinaryParams from_base64(char a = '+', char b = '/', char c = '=');

		std::string fmt_BinaryData(const BinaryData& data);
		std::string fmt_string();
	};
}
namespace NSROOT = dog_torch::serialize;

NSROOT::BinaryParams NSROOT::BinaryParams::from_utf8()
{
	auto params = BinaryParams();
	params.type_ = Type::UTF_8;
	return params;
}
NSROOT::BinaryParams NSROOT::BinaryParams::from_binary()
{
	auto params = BinaryParams();
	params.type_ = Type::Binary;
	return params;
}

NSROOT::BinaryParams NSROOT::BinaryParams::from_hex(bool is_upper)
{
	auto params = BinaryParams();
	params.type_ = Type::Hex;
	params.params_.push_back(is_upper);
	return params;
}
NSROOT::BinaryParams NSROOT::BinaryParams::from_base64(char a, char b, char c)
{
	auto params = BinaryParams();
	params.type_ = Type::Hex;
	params.params_.push_back(a);
	params.params_.push_back(b);
	params.params_.push_back(c);
	return params;
}
std::string NSROOT::BinaryParams::fmt_BinaryData(const BinaryData& data)
{
	switch (type_)
	{
	case Type::Binary:
		return data.to_bin_string();
	case Type::Hex:
		return data.to_hex_string(std::get<bool>(this->params_[0]));
	case Type::Base64:
		return data.to_base64_string(
			std::get<char>(this->params_[0]), 
			std::get<char>(this->params_[1]), 
			std::get<char>(this->params_[2])
		);
	default:
		return data.to_string();
	}
}

std::string NSROOT::BinaryParams::fmt_string()
{
	switch(type_)
	{
	case Type::Hex:
		return std::format("{}:{}", 
			type_fmt_string(this->type_), 
			(std::get<bool>(this->params_[0]) ? "upper" : "lower")
		);
	case Type::Base64:
		return std::format("{}:{}{}{}",
			type_fmt_string(this->type_),
			std::get<char>(this->params_[0]),
			std::get<char>(this->params_[1]),
			std::get<char>(this->params_[2])
		);
	default:
		return type_fmt_string(this->type_);
	}
}

std::string NSROOT::type_fmt_string(Type type)
{
	switch (type)
	{
	case Type::UTF_8: return "UTF-8";
	case Type::Binary: return "Binary";
	case Type::Hex: return "Hex";
	case Type::Base64: return "Base64";
	}
}

#ifdef _WIN32
#include <windows.h>
void enableVirtualTerminal() {
    SetConsoleCP(65001);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}
void clear_cmd()
{
    system("cls");
}
void pause_cmd()
{
    system("pause");
    clear_cmd();
}
#else
void clear_cmd()
{
    system("clear");
}

void enableVirtualTerminal() {}
void pause_cmd()
{
    printf("Press any key to continue . . .\n");
    while (getchar() != '\n');  // 清空缓冲区
    getchar();                  // 等待回车
    clear_cmd();
}
#endif


void using_mode();
void onetime_mode(const std::vector<std::string>& args);

int main(int argc, char** argv) {
    enableVirtualTerminal();
    if (argc == 1)
    {
        using_mode();
    }
    else
    {
        std::vector<std::string> args;
        for (int i = 1; i < argc; i++)
        {
            args.push_back(argv[i]);
        }
        onetime_mode(args);
    }
    return 0;
}

using dog_torch::serialize::BinaryData;
using dog_torch::serialize::BinaryParams;
using serializeType = dog_torch::serialize::Type;
namespace fs = std::filesystem;
std::optional<bool> input_bool()
{
    std::cout << "bool input\n";
    std::cout << "true  <- 1 true  True   t  T  y  Y  yes  Yes\n";
    std::cout << "false <- 0 false False  f  F  n  N  no   No\n";
    std::cout << ">";
    std::cout.flush();
    std::string str2;
    std::getline(std::cin, str2);
    if (str2 == "0" || 
        str2 == "false" || str2 == "False" || str2 == "f" || str2 == "F" || 
        str2 == "n" || str2 == "N" || str2 == "no" || str2 == "No")
    {
        return false;
    }
    else if (str2 == "1" || 
        str2 == "true" || str2 == "True" || str2 == "t" || str2 == "T" || 
        str2 == "y" || str2 == "Y" || str2 == "yes" || str2 == "Yes")
    {
        return true;
    }
    std::cout << "invalid param or arg" << std::endl;
    std::cin.ignore();
    return std::nullopt;
}
std::optional<uint64_t> input_uint64(bool allow_empty = false)
{
    if(!allow_empty)
    {
        std::string str2;
        std::getline(std::cin, str2);
        uint64_t tar_region = 0;
        try
        {
            tar_region = std::stoull(str2);
            return tar_region;
        }
        catch (std::exception& e)
        {
            std::cout << "invalid param or arg" << std::endl;
            return std::nullopt;
        }
    }
    else
    {
        char c = 0;
        std::string str;
        do
        {
            c = std::cin.get();
            str += c;
        } while (c != '\n');
        if (str.size() == 1 && str[0] == '\n')
        {
            return std::nullopt;
        }
        uint64_t tar_region = 0;
        try
        {
            tar_region = std::stoull(str);
            return tar_region;
        }
        catch (std::exception& e)
        {
            std::cout << "invalid param or arg" << std::endl;
            return std::nullopt;
        }
    }
}
std::string input_string()
{
    std::cout << "string input\n";
    std::cout << ">";
    std::cout.flush();
    std::string str2;
    std::getline(std::cin, str2);
    return str2;
}
std::optional<BinaryData> input_binary(bool allow_empty, bool empty_random, uint64_t size, std::string* ori_str = nullptr, uint64_t* type = nullptr)
{
    std::cout << std::format("binary input {}",
        allow_empty == true && empty_random == true ? "will be random when input is empty" : ""
        ) << std::endl;
    std::cout << "1. choose type: utf8-0,bin-1,hex-2,base64-3" << std::endl;
    std::cout << "2. input data and press enter to continue" << std::endl;
    std::cout << ">";
    std::optional<uint64_t>  op = input_uint64(true);
    if (!op.has_value() && allow_empty)
    {
        if (!empty_random)
        {
            return BinaryData{};
        }
        else
        {
            std::random_device rd;
            BinaryData r{ size };
            for (auto& i : r)
            {
                i = static_cast<uint8_t>(rd());
            }
            return r;
        }
    }
    else if (!op.has_value())
    {
        std::cout << "unsupport empty" << std::endl;
        return std::nullopt;
    }
    std::string str = input_string();
    if (op < 4)
    {
        if(ori_str) *ori_str = str;
        if (type) *type = op.value();
        return BinaryData{ str, op.value() };
    }
    else
    {
        std::cout << "invalid operation" << std::endl;
        return std::nullopt;
    }
}
std::optional<std::variant<BinaryData, fs::path>> input_data(bool allow_file, bool allow_empty, uint64_t& type, std::string& input_str)
{
    std::cout << "binary input" << std::endl;
    std::cout << std::format("1. choose type: utf8-0,bin-1,hex-2,base64-3{}", (allow_file ? ",file-4" : "")) << std::endl;
    std::cout << "2. input data and press enter to continue" << std::endl;
    std::cout << ">";
    std::optional<uint64_t>  op = input_uint64(true);
    if (!op.has_value() && allow_empty)
    {
        return BinaryData{};
    }
    else if (!op.has_value())
    {
        std::cout << "unsupport empty" << std::endl;
        return std::nullopt;
    }
    std::string str = input_string();
    input_str = str;
    if (op == 4 && !allow_file)
    {
        std::cout << "file input not allowed" << std::endl;
        return std::nullopt;
    }
    else if (op < 4)
    {
        type = op.value();
        return BinaryData{ str, op.value()};
    }
    else if (op == 4)
    {
        type = op.value();
        if (!fs::exists(str))
        {
            std::cout << "file not exists" << std::endl;
            return std::nullopt;
        }
        return fs::path{ str };
    }
    else
    {
        std::cout << "invalid operation" << std::endl;
        return std::nullopt;
    }
}
std::optional<std::variant<BinaryParams, fs::path>> output_type(bool allow_file)
{
    std::cout << "output" << std::endl;
    std::cout << std::format("1. choose type: utf8-0,bin-1,hex-2:lower/0|upper/1,base64-3:[replace]*3{}", (allow_file ? ",file-4:path" : "")) << std::endl;
    std::cout << "e.m." << std::endl;
    std::cout << "2:0->hex:upper 3:+-=" << std::endl;
    std::cout << ">";

    std::optional<uint64_t>  op = input_uint64(true);
    if (!op.has_value())
    {
        std::cout << "unsupport empty" << std::endl;
        return std::nullopt;
    }
    if (op == 4 && !allow_file)
    {
        std::cout << "file input not allowed" << std::endl;
        return std::nullopt;
    }
    else if (op < 4)
    {
        switch (op.value())
        {
        case 0: return BinaryParams::from_utf8();
        case 1: return BinaryParams::from_binary();
        case 2: return BinaryParams::from_hex(true);
        case 3: return BinaryParams::from_base64();
        }
    }
    else if (op == 4)
    {
        std::string str = input_string();
        std::string path_str = str.substr(2);
        auto writeable = [](const std::string& str)->bool
            {
                fs::path p{ str };
                std::error_code ec;
                fs::perms perms;
                if (fs::exists(p))
                {
                    if (!fs::is_regular_file(p)) return false;
                    perms = fs::status(p, ec).permissions();

                }
                else
                {
                    auto pp = p.parent_path();
                    perms = fs::status(pp, ec).permissions();
                }
                if (ec) return false;
                return (perms & fs::perms::owner_write) != fs::perms::none ||
                    (perms & fs::perms::group_write) != fs::perms::none ||
                    (perms & fs::perms::others_write) != fs::perms::none;
            };
        if (!writeable(path_str))
        {
            std::cout << "file not writeable" << std::endl;
            return std::nullopt;
        }
        return fs::path{ path_str };
    }
    else
    {
        std::cout << "invalid operation" << std::endl;
        return std::nullopt;
    }
}
using dog_torch::crypto::hash::Generator;
namespace hash = dog_torch::crypto::hash;
enum class TaskType : uint64_t
{
    Hash = 0,
    Crypt = 1,
};
std::shared_ptr<Generator> get_hash_generator()
{
    //name
    std::cout << "choose hash function:" << std::endl;
    using dog_torch::math::region::NumberIterator;
    auto config_list = hash::algorithm::get_all();
    for (auto config : config_list)
    {
        std::cout << config.get().name << ',';
    }
    std::cout << std::endl;
    std::string name = input_string();
    
    //effective
    bool found = false;
    hash::algorithm::Config tar_config{ "","",{} };
    for (auto config : config_list)
    {
        if (config.get().name == name)
        {
            tar_config = config.get();
            found = true;
        }
    }
    if (!found)
    {
        std::cout << "invalid param or arg" << std::endl;
        return nullptr;
    }
    NumberIterator nit{ tar_config.region };
    while (nit.have_next())
    {
        std::cout << nit.next() << ',';
    }
    std::cout << std::endl << ">";
    auto effective = input_uint64();
    if (!effective.has_value()) return nullptr;
    
    //params
    using dog_torch::crypto::Param;
    std::unordered_map<std::string, Param> tar_params;
    for (auto [k, v] : tar_config.params)
    {
        std::cout << std::format("{}:{},", k, dog_torch::crypto::get_type_name(v.type));
        if (v.type == dog_torch::crypto::ParamType::Bool)
        {
            auto arg = input_bool();
            if (!arg.has_value()) return nullptr;
            tar_params[k] = arg.value();
        }
        else if (v.type == dog_torch::crypto::ParamType::UInt64)
        {
            auto arg = input_uint64();
            if (!arg.has_value()) return nullptr;
            tar_params[k] = arg.value();
        }
        else if (v.type == dog_torch::crypto::ParamType::String)
        {
            auto arg = input_string();
            tar_params[k] = arg;
        }
        else if (v.type == dog_torch::crypto::ParamType::Binary)
        {
            uint64_t t;
            std::string s;
            auto arg = input_data(false, true, t, s);
            tar_params[k] = std::get<0>(arg.value());
        }

    }
    using dog_torch::crypto::hash::algorithm::create;
    return std::make_shared<Generator>(create(name, effective.value(), tar_params));
}
using dog_torch::async::pool::PausedThreadPool;
using dog_torch::async::thread::PauseableDetail;
struct HashThreadResult
{
    BinaryData output;
    PauseableDetail detail;
    HashThreadResult(const BinaryData& output, const PauseableDetail& detail) : output(output), detail(detail) {}
};
struct HashResult
{
    fs::path input_path;
    BinaryParams output_type;
    std::shared_future<HashThreadResult> result;
    HashResult(
        const fs::path& input_path_,
        const BinaryParams& output_type_,
        const std::shared_future<HashThreadResult>& result_
    ) : input_path(input_path_),output_type(output_type_), result{ result_ } {}
    HashResult() = default;
    template <class Rep, class Per>
    std::future_status wait_for(const std::chrono::duration<Rep, Per>& Rel_time) const
    {
        return result.wait_for(Rel_time);
    }
    std::string get_binary_str()
    {
        auto out = result.get().output;
        return output_type.fmt_BinaryData(out);
    }
    std::string get_config_str()
    {
        return std::any_cast<std::string>(result.get().detail.params.at("config_str"));
    }
    std::string get_input_path_str()
    {
        return input_path.string();
    }
};
void handle_trans()
{
    std::string str;
    uint64_t type = 0;
    auto data = input_data(false, false, type, str);
    if (!data.has_value()) return;
    auto ot = output_type(false);
    if (!ot.has_value()) return;
    auto arr = std::get<0>(ot.value());
    auto tar_str = arr.fmt_BinaryData(std::get<0>(data.value()));
    clear_cmd();
    using dog_torch::serialize::type_fmt_string;
    std::cout << "=====input=====" << "\n";
    std::cout << str << "\n";
    std::cout << "=====operate=====" << "\n";
    std::cout << std::format("{}->{}", type_fmt_string(static_cast<serializeType>(type)), arr.fmt_string()) << "\n";
    std::cout << "=====output=====" << "\n";
    std::cout << tar_str << "\n";
    std::cout << std::endl;
}
void handle_hash(
    PausedThreadPool& pool,
    std::unordered_map<uint64_t, HashResult>& hash_results
)
{
    std::string str;
    uint64_t type = 0;
    auto data = input_data(true, true, type, str);
    if (!data.has_value()) return;
    auto ot = output_type(false);
    if (!ot.has_value()) return;
    auto gen = get_hash_generator();
    if (gen == nullptr) return;
    if (!ot.has_value()) return;
    auto arr = std::get<0>(ot.value());
    if (data.value().index() == 0)
    {
        data = gen->calculate(std::get<0>(data.value()));
        auto tar_str = arr.fmt_BinaryData(std::get<0>(data.value()));
        using dog_torch::serialize::type_fmt_string;
        std::cout << "=====input=====" << "\n";
        std::cout << str << "\n";
        std::cout << "=====operate=====" << "\n";
        std::cout << std::format("{}-[{}]->{}", type_fmt_string(static_cast<serializeType>(type)), gen->fmt_string(), arr.fmt_string()) << "\n";
        std::cout << "=====hash=====" << "\n";
        std::cout << tar_str << "\n";
    }
    else
    {
        auto fpath = std::get<1>(data.value());
        auto result = pool.add_task(
            [gen](dog_torch::async::thread::PauseableChannel& pc, fs::path path)
            {
                pc.param("type") = TaskType::Hash;
                pc.param("path") = path.string();
                std::ifstream ifs(path, std::ios::binary);
                uint64_t size = fs::file_size(path);
                pc.param("config_str") = gen->fmt_string();
                auto data = hash::Generator::calculate_with(pc, *gen, ifs, size);
                if (pc.is_cancel())
                {
                    data = BinaryData{};
                }
                return HashThreadResult(std::move(data), std::move(pc.to_detail()));
            },
            fpath
        );
        hash_results[result.task_id] = HashResult{
            fpath, std::get<0>(ot.value()),result.share().future
        };
        std::cout << "success to add task query, id is " << result.task_id << "\n";
    }
}
std::string fmt_iso_time(uint64_t milis_time)
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
}
using dog_torch::async::pool::Result;
using dog_torch::async::pool::SharedResult;
using dog_torch::async::thread::PauseableDetail;
void task_manage(
    PausedThreadPool& pool, 
    std::unordered_map<uint64_t, HashResult>& hash_results,
    std::vector<SharedResult<PauseableDetail>>& crypto_result
)
{
    clear_cmd();
    std::optional<uint64_t> op;
    do
    {
        auto details = pool.get_tasks_detail();
        using dog_torch::async::status_to_string;
        std::cout << "=====hash result=====" << "\n";
        for (auto& [id, future] : hash_results)
        {
            using std::chrono::microseconds;
            if (future.wait_for(microseconds(1)) == std::future_status::ready)
            {
                std::cout << "{" << "\n";
                std::cout << " =====input=====\n";
                std::cout << future.get_input_path_str() << "\n";
                std::cout << " =====operate=====\n";
                std::cout << std::format("file-[{}]->{}\n", future.get_config_str(), future.output_type.fmt_string());
                std::cout << " =====hash=====\n";
                std::cout << future.get_binary_str() << "\n";
                std::cout << "}\n";
            }
        }
        std::cout.flush();
        for (auto& crypt : crypto_result)
        {
            using std::chrono::microseconds;
            if (crypt.future.wait_for(microseconds(1)) == std::future_status::ready)
            {
                std::cout << std::format("id: {}\n", crypt.task_id);
                std::cout << "=====plain=====" << "\n";
                std::cout << std::any_cast<std::string>(crypt.future.get().params.at("plain")) << "\n";
                std::cout << "=====key=====" << "\n";
                std::cout << std::any_cast<std::string>(crypt.future.get().params.at("key")) << "\n";
                std::cout << "=====operate=====" << "\n";
                std::cout << std::any_cast<std::string>(crypt.future.get().params.at("config_str")) << "\n";
                std::cout << "=====crypt=====" << "\n";
                std::cout << std::any_cast<std::string>(crypt.future.get().params.at("crypt")) << "\n";
                std::cout << "=====result=====" << "\n";
                std::cout << std::any_cast<std::string>(crypt.future.get().params.at("status")) << "\n";
            }
        }
        std::cout << "=====tasks deatil=====" << "\n";
        for (auto& detail : details)
        {
            std::cout << "{" << "\n";
            if (std::any_cast<TaskType>(detail.params.at("type")) == TaskType::Hash)
            {
                std::cout << std::format("id: {}\n", detail.task_id);
                std::cout << " =====input=====\n";
                std::cout << hash_results[detail.task_id].get_input_path_str() << "\n";
                std::cout << " =====operate=====\n";
                std::cout << std::format("file-[{}]->{}\n", std::any_cast<std::string>(detail.params.at("config_str")), hash_results[detail.task_id].output_type.fmt_string());
            }
            else if (std::any_cast<TaskType>(detail.params.at("type")) == TaskType::Crypt)
            {
                std::cout << std::format("id: {}\n", detail.task_id);
                std::cout << "=====plain=====" << "\n";
                std::cout << std::any_cast<std::string>(detail.params.at("plain")) << "\n";
                std::cout << "=====key=====" << "\n";
                std::cout << std::any_cast<std::string>(detail.params.at("key")) << "\n";
                std::cout << "=====operate=====" << "\n";
                std::cout << std::any_cast<std::string>(detail.params.at("config_str")) << "\n";
                std::cout << "=====crypt=====" << "\n";
                std::cout << std::any_cast<std::string>(detail.params.at("crypt")) << "\n";
            }
            std::cout << std::format("status: {}\n", status_to_string(detail.status));
            std::cout << std::format("progress: {:0.2f}%\n", detail.progress * 100);
            std::cout << std::format("time: {}\n", fmt_iso_time(detail.time), detail.time);
            uint64_t elapsed = static_cast<uint64_t>(detail.time * (1 / detail.progress - 1));
            std::cout << std::format("expected: ~ {}\n", fmt_iso_time(elapsed), elapsed);
            std::cout << "}\n";
        };
        std::cout.flush();
        std::cout << "operation code" << "\n";
        std::cout << "1. pause" << "\n";
        std::cout << "2. resume" << "\n";
        std::cout << "3. cancel" << "\n";
        std::cout << "0. exit" << "\n";
        std::cout << ">";
        std::cout.flush();
        try
        {
            do
            {
                op = input_uint64(true);
                if (!op.has_value()) break;
                if (op == 0)
                {
                    break;
                }
                std::cout << "task id:\n>";
                auto id = input_uint64();
                if (!id.has_value()) break;
                if (op == 1)
                {
                    if (pool.pause(id.value()))
                    {
                        std::cout << std::format("success to pause task {}", id.value()) << std::endl;
                    }
                    else
                    {
                        std::cout << std::format("task {} is not running", id.value()) << std::endl;
                    }
                }
                else if (op == 2)
                {
                    if (pool.resume(id.value()))
                    {
                        std::cout << std::format("success to resume task {}", id.value()) << std::endl;
                    }
                    else
                    {
                        std::cout << std::format("task {} is not paused", id.value()) << std::endl;
                    }
                }
                else if (op == 3)
                {
                    if (pool.cancel(id.value()))
                    {
                        std::cout << std::format("success to cancel task {}", id.value()) << std::endl;
                    }
                    else
                    {
                        std::cout << std::format("task {} is not running", id.value()) << std::endl;
                    }
                }
                else
                {
                    std::cout << "invalid operation code" << std::endl;
                }
            } while (false);
            pause_cmd();
        }
        catch (std::exception& e)
        {
            std::cout << e.what() << std::endl;
        }
    } while (!op.has_value() || op.value() != 0);
}
namespace block_crypto = dog_torch::crypto::sym::block;
std::string get_padding()
{
    std::cout << "choose padding" << "\n";
    auto padding_configs = block_crypto::padding::get_all();
    for (uint64_t i = 0; i < padding_configs.size(); ++i)
    {
        std::cout << std::format("{}: {}\n", i, padding_configs[i].get().name);
    }
    std::cout << ">";
    std::cout.flush();
    auto padding_config = input_uint64();
    if (!padding_config.has_value())
    {
        return "";
    }
    if (padding_config.value() >= padding_configs.size())
    {
        std::cout << "invalid padding index" << std::endl;
        return "";
    }
    return padding_configs[padding_config.value()].get().name;
}
std::shared_ptr<block_crypto::BlockCipher> get_block_cipher()
{
    std::cout << "choose algorithm" << "\n";
    auto alg_configs = block_crypto::algorithm::get_all();
    for (auto& config : alg_configs)
    {
        std::cout << config.get().name << ",";
    }
    std::cout << std::endl;
    std::string alg_name = input_string();

    auto alg_config = std::find_if(alg_configs.begin(), alg_configs.end(), [&alg_name](const auto& config)
        {
            return config.get().name == alg_name;
        }
    );
    if (alg_config == alg_configs.end())
    {
        std::cout << "invalid algorithm name" << std::endl;
        return nullptr;
    }

    using dog_torch::math::region::NumberIterator;
    NumberIterator bnit{ (*alg_config).get().block_size_region };
    std::cout << "choose block size" << "\n";
    while (bnit.have_next())
    {
        std::cout << bnit.next() << ",";
    }
    std::cout << "\n>";
    std::cout.flush();
    auto block_size = input_uint64();
    if (!block_size.has_value())
    {
        return nullptr;
    }

    NumberIterator knit{ (*alg_config).get().key_size_region };
    std::cout << "choose key size" << "\n";
    while (knit.have_next())
    {
        std::cout << knit.next() << ",";
    }
    std::cout << "\n>";
    std::cout.flush();
    auto key_size = input_uint64();
    if (!key_size.has_value())
    {
        return nullptr;
    }

    std::unique_ptr<block_crypto::algorithm::Algorithm> alg_ptr = nullptr;
    try
    {
        alg_ptr = block_crypto::algorithm::create((*alg_config).get().name, block_size.value(), key_size.value());
        if (alg_ptr == nullptr)
        {
            return nullptr;
        }
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;
        return nullptr;
    }

    auto modes = block_crypto::mode::get_all();
    std::cout << "choose mode" << "\n";
    for (auto& mode : modes)
    {
        std::cout << mode.get().name << ",";
    }
    std::cout << std::endl;
    auto mode_name = input_string();
    auto mode_config = std::find_if(modes.begin(), modes.end(), [&mode_name](const auto& mode)
        {
            return mode.get().name == mode_name;
        }
    );
    if (mode_config == modes.end())
    {
        std::cout << "invalid mode name" << std::endl;
        return nullptr;
    }
    using dog_torch::crypto::Param;
    std::unordered_map<std::string, Param> tar_params;
    for (auto [k, v] : mode_config->get().params)
    {
        std::cout << std::format("{}:{},", k, dog_torch::crypto::get_type_name(v.type));
        if (v.type == dog_torch::crypto::ParamType::Bool)
        {
            auto arg = input_bool();
            if (!arg.has_value()) return nullptr;
            tar_params[k] = arg.value();
        }
        else if (v.type == dog_torch::crypto::ParamType::UInt64)
        {
            std::cout << "\n>";
            std::cout.flush();
            auto arg = input_uint64();
            if (!arg.has_value()) return nullptr;
            tar_params[k] = arg.value();
        }
        else if (v.type == dog_torch::crypto::ParamType::String)
        {
            auto arg = input_string();
            tar_params[k] = arg;
        }
        else if (v.type == dog_torch::crypto::ParamType::Binary)
        {
            auto arg = input_binary(true, k == "iv", alg_ptr->get_block_size());
            if (!arg.has_value()) return nullptr;
            tar_params[k] = arg.value();
        }
    }

    auto padding_name = get_padding();
    if (padding_name == "")
    {
        return nullptr;
    }
    auto padding = block_crypto::padding::create(padding_name);

    auto mode = block_crypto::mode::create(mode_config->get().name, *padding, tar_params);
    if (mode == nullptr)
    {
        return nullptr;
    }
    return std::make_shared<block_crypto::BlockCipher>(*alg_ptr, *mode);
}
using dog_torch::serialize::tlv::Value;
std::shared_ptr<block_crypto::BlockCipher> parse_block_cipher(Value value)
{
    namespace tlv = dog_torch::serialize::tlv;
    using dog_torch::crypto::Param;
    const auto& root_obj = value.to_object();
    if (root_obj.size() != 1 || root_obj.find(tlv::MIBString{ "Block" }) == root_obj.end())
    {
        std::cout << "head not found" << std::endl;
        return nullptr;
    }
    const auto& cipher_config = root_obj.at(tlv::MIBString{ "Block" }).to_array();
    const auto& algorithm_configs = cipher_config.at(0).to_array();
    std::string alg_name = algorithm_configs.at(0).to_string().string;
    uint64_t block_size = algorithm_configs.at(1).to_integer().number;
    uint64_t key_size = algorithm_configs.at(2).to_integer().number;
    auto alg_ptr = block_crypto::algorithm::create(alg_name, block_size, key_size);
    if (alg_ptr == nullptr)
    {
        std::cout << "algorithm not support" << std::endl;
        return nullptr;
    }
    const auto& mode_configs = cipher_config.at(1).to_array();
    std::string mode_name = mode_configs.at(0).to_string().string;
    std::string paddding_name = mode_configs.at(1).to_string().string;
    auto padding = block_crypto::padding::create(paddding_name);
    if (padding == nullptr)
    {
        std::cout << "padding not support" << std::endl;
        return nullptr;
    }
    const auto& mode_args = mode_configs.at(2).to_object();
    std::unordered_map<std::string, Param> tar_params;
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
    auto mode = block_crypto::mode::create(mode_name, *padding, tar_params);
    if (mode == nullptr)
    {
        std::cout << "mode not support" << std::endl;
        return nullptr;
    }
    return std::make_shared<block_crypto::BlockCipher>(*alg_ptr, *mode);

}
void handle_sym_crypt(PausedThreadPool& pool, std::vector<SharedResult<PauseableDetail>>& crypto_result)
{
    using dog_torch::serialize::tlv::Value;
    std::optional<uint64_t> op = 0;
    std::cout << "1. encrypt" << "\n";
    std::cout << "2. decrypt" << "\n>";
    std::cout.flush();
    op = input_uint64(true);
    if (!op.has_value() || (op != 1 && op != 2))
    {
        std::cout << "invalid operation code" << std::endl;
        return;
    }
    if (op == 1)
    {
        std::string str;
        uint64_t type = 0;
        std::cout << "plain ";
        auto data = input_data(true, true, type, str);
        auto ot = output_type(true);
        if (!ot.has_value()) return;
        if (data.value().index() != ot.value().index())
        {
            std::cout << "plain and crypt type not match" << std::endl;
            return;
        }
        auto block_cipher = get_block_cipher();
        std::cout << "key ";
        std::string key_str = "";
        uint64_t key_type = 0;
        auto key = input_binary(false, false, 0, &key_str, &key_type);
        if (!key.has_value()) return;
        block_cipher->set_key(key.value());
        std::cout << "add head in front of crypt data? (do not input how to do when decrypt)" << "\n";
        auto add_head = input_bool();
        if (!add_head.has_value()) return;

        if (data.value().index() == 0)
        {
            clear_cmd();

            auto out_type = std::get<0>(ot.value());

            std::cout << "=====plain=====" << "\n";
            std::cout << str << "\n";
            std::cout << "=====key=====" << "\n";
            std::cout << std::format("{}:{}", type_fmt_string(static_cast<serializeType>(key_type)), key_str) << "\n";
            std::cout << "=====operate=====" << "\n";
            std::cout << std::format("{}-[{}]->{}{}", 
                type_fmt_string(static_cast<serializeType>(type)), 
                block_cipher->fmt_string(),
                add_head ? "BlockCipher config|" : "",
                out_type.fmt_string()
            ) << "\n";

            try
            {
                BinaryData plain = std::get<0>(data.value());
                BinaryData crypt;
                if (add_head.value())
                {
                    crypt += BinaryData{ block_cipher->serialize().serialize() };
                }
                block_cipher->init();
                crypt += block_cipher->encrypt(plain);
                std::string out_str = out_type.fmt_BinaryData(crypt);

                std::cout << "=====crypt=====" << "\n";
                std::cout << out_str << "\n";
            }
            catch (std::exception& e)
            {
                std::cout << "=====error=====" << "\n";
                std::cout << e.what() << std::endl;
            }
        }
        else
        {
            auto plain_path = std::get<1>(data.value());
            auto crypt_path = std::get<1>(ot.value());
            std::string fmt_key = std::format("{}:{}", type_fmt_string(static_cast<serializeType>(key_type)), key_str);
            auto task = pool.add_task(
                [add_head_ = add_head.value(), block_cipher, fmt_key]
                (dog_torch::async::thread::PauseableChannel& pc, fs::path plain, fs::path crypt) -> PauseableDetail
                {
                    //todo test
                    pc.param("type") = TaskType::Crypt;
                    pc.param("plain") = plain.string();
                    pc.param("crypt") = crypt.string();
                    pc.param("key") = fmt_key;
                    uint64_t plain_size = fs::file_size(plain);
                    std::ifstream plain_stream(plain, std::ios::binary);
                    std::ofstream crypt_stream(crypt, std::ios::binary);
                    if (add_head_)
                    {
                        BinaryData file_head;
                        file_head += block_cipher->serialize().serialize();
                        crypt_stream.write(file_head.data_stream(), file_head.size());
                    }
                    block_cipher->init();
                    pc.param("config_str") = block_cipher->fmt_string();
                    try
                    {
                        block_cipher->encryptp_stream(pc, plain_stream, plain_size, crypt_stream);
                        pc.param("result") = std::string("success");
                    }
                    catch (std::exception& e)
                    {
                        pc.param("result") = std::string(e.what());
                    }
                    return pc.to_detail();
                },
                plain_path, crypt_path
            );
            std::cout << "success to add task query, id is " << task.task_id << "\n";
            crypto_result.emplace_back(task.share());
        }
    }
    else if (op == 2)
    {
        std::string str;
        uint64_t type = 0;
        std::cout << "plain ";
        auto data = input_data(true, true, type, str);
        auto ot = output_type(true);
        if (!ot.has_value()) return;
        if (data.value().index() != ot.value().index())
        {
            std::cout << "plain and crypt type not match" << std::endl;
            return;
        }
        std::cout << "with head in front of crypt data? (Do you add head when encrypt?)" << "\n";
        uint64_t head_size = 0;
        auto add_head = input_bool();
        if (!add_head.has_value()) return;
        std::shared_ptr<block_crypto::BlockCipher> block_cipher = nullptr;
        if (!add_head.value())
        {
            block_cipher = get_block_cipher();
        }
        else
        {
            namespace tlv = dog_torch::serialize::tlv;
            using dog_torch::crypto::Param;
            Value value;
            if (data.value().index() == 0)
            {
                const auto& bin_data = std::get<0>(data.value());
                std::vector<uint8_t>::const_iterator cit = bin_data.cbegin();
                std::vector<uint8_t>::const_iterator end = bin_data.cend();
                value = Value::parse(cit, end);
                data = bin_data.sub_bytes_pos(cit, end);
            }
            else
            {
                std::ifstream ifs(std::get<1>(data.value()), std::ios::binary);
                value = Value::parse(ifs);
                head_size = ifs.tellg();
            }
            block_cipher = parse_block_cipher(value);
        }
        if (block_cipher == nullptr)
        {
            std::cout << "block cipher not support" << std::endl;
            return;
        }
        std::cout << "key ";
        std::string key_str = "";
        uint64_t key_type = 0;
        auto key = input_binary(false, false, 0, &key_str, &key_type);
        if (!key.has_value()) return;
        block_cipher->set_key(key.value());

        if (data.value().index() == 0)
        {
            clear_cmd();

            auto out_type = std::get<0>(ot.value());

            std::cout << "=====crypt=====" << "\n";
            std::cout << str << "\n";
            std::cout << "=====key=====" << "\n";
            std::cout << std::format("{}:{}", type_fmt_string(static_cast<serializeType>(key_type)), key_str) << "\n";
            std::cout << "=====operate=====" << "\n";
            std::cout << std::format("{}{}-[{}]->{}",
                add_head ? "BlockCipher config|" : "",
                type_fmt_string(static_cast<serializeType>(type)),
                block_cipher->fmt_string(),
                out_type.fmt_string()
            ) << "\n";

            try
            {
                BinaryData crypt = std::get<0>(data.value());
                BinaryData plain;
                block_cipher->init();
                plain = block_cipher->decrypt(crypt);
                std::string out_str = out_type.fmt_BinaryData(plain);

                std::cout << "=====plain=====" << "\n";
                std::cout << out_str << "\n";
            }
            catch (std::exception& e)
            {
                std::cout << "=====error=====" << "\n";
                std::cout << e.what() << std::endl;
            }
        }
        else
        {
            auto crypt_path = std::get<1>(data.value());
            auto plain_path = std::get<1>(ot.value());
            std::string fmt_key = std::format("{}:{}", type_fmt_string(static_cast<serializeType>(key_type)), key_str);
            auto task = pool.add_task(
                [add_head_ = add_head.value(), block_cipher, fmt_key, head_size]
                (dog_torch::async::thread::PauseableChannel& pc, fs::path crypt, fs::path plain) -> PauseableDetail
                {
                    //todo test
                    pc.param("type") = TaskType::Crypt;
                    pc.param("plain") = plain.string();
                    pc.param("crypt") = crypt.string();
                    pc.param("key") = fmt_key;
                    uint64_t crypt_size = fs::file_size(crypt) - head_size;
                    std::ifstream crypt_stream(crypt, std::ios::binary);
                    crypt_stream.seekg(head_size);
                    std::ofstream plain_stream(plain, std::ios::binary);
                    block_cipher->init();
                    pc.param("config_str") = block_cipher->fmt_string();
                    try
                    {
                        block_cipher->decryptp_stream(pc, crypt_stream, crypt_size, plain_stream);
                        pc.param("status") = std::string("success");
                    }
                    catch (std::exception& e)
                    {
                        pc.param("status") = std::string(e.what());
                    }
                    return pc.to_detail();
                },
                crypt_path, plain_path
            );
            crypto_result.emplace_back(task.share());
            std::cout << "success to add task query, id is " << task.task_id << "\n";
        }
    }
}

void using_mode()
{
    std::cout << "console mode only support fewer features" << "\n";
    std::cout << "please use GUI mode" << "\n";
    std::cout.flush();

    PausedThreadPool pool{ 1 };
    pool.start();

    std::unordered_map<uint64_t, HashResult> hash_results;
    std::vector<SharedResult<PauseableDetail>> crypt_results;
    std::optional<uint64_t> op = 0;
    do
    {
        std::cout << "operation code" << "\n";
        std::cout << "1. binary     encode/decode" << "\n";
        std::cout << "2. hash" << "\n";
        std::cout << "3. symmetric  encrypt/decrypt" << "\n";
        //std::cout << "4. asymmetric encrypt/decrypt" << "\n";
        std::cout << "5. tasks manager" << "\n";
        std::cout << "0. exit" << "\n";
        std::cout << ">";
        std::cout.flush();
        try
        {
            op = input_uint64(true);
            if (!op.has_value()) {}
            else if (op == 1)
            {
                handle_trans();
            }
            else if (op == 2)
            {
                handle_hash(pool, hash_results);
            }
            else if (op == 3)
            {
                handle_sym_crypt(pool, crypt_results);
            }
            else if (op == 5)
            {
                task_manage(pool, hash_results, crypt_results);
            }
        }
        catch (std::exception& e)
        {
            std::cout << e.what() << std::endl;
        }
        pause_cmd();
    }while (op != 0);
}
void onetime_mode(const std::vector<std::string>& args)
{

}