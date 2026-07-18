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
#include "serialize_extra/BinaryParams.h"

#include "crypto/hash/hash_algorithms.h"

void enableVirtualTerminal();
void clear_cmd();
void pause_cmd();


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
    std::string str2;
    std::getline(std::cin, str2);
    if (str2 == "0" || str2 == "false" || str2 == "False" || str2 == "f" || str2 == "F" || str2 == "n" || str2 == "N")
    {
        return false;
    }
    else if (str2 == "1" || str2 == "true" || str2 == "True" || str2 == "t" || str2 == "T" || str2 == "y" || str2 == "Y")
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
    if (op == 4 && !allow_file)
    {
        std::cout << "file input not allowed" << std::endl;
        return std::nullopt;
    }
    else if (op < 4)
    {
        return BinaryData{ str, op.value()};
    }
    else if (op == 4)
    {
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
    std::string str;
    std::getline(std::cin, str);
    if (str.size() == 1 && str[0] < '4' && str[0] >= '0')
    {
        switch (str[0])
        {
        case '0': return BinaryParams::from_utf8();
        case '1': return BinaryParams::from_binary();
        case '2': return BinaryParams::from_hex(true);
        case '3': return BinaryParams::from_base64();
        }
    }
    if (str.size() <= 2 || str[1] != ':')
    {
        std::cout << "invalid operation" << std::endl;
        return std::nullopt;
    }
    if (str[0] == '2')
    {
        if (str[2] == '0')
        {
            return BinaryParams::from_hex(true);
        }
        else if (str[2] == '1')
        {
            return BinaryParams::from_hex(false);
        }
        else if (str.substr(2) == "lower" || str.substr(2) == "upper")
        {
            return BinaryParams::from_hex(str.substr(2) == "upper");
        }
        else
        {
            std::cout << "invalid operation" << std::endl;
            return std::nullopt;
        }
    }
    if (str[0] == '3')
    {
        if (str.size() != 5)
        {
            std::cout << "invalid operation" << std::endl;
            return std::nullopt;
        }
        char c1 = str[2], c2 = str[3], c3 = str[4];
        auto contain = [](char c) -> bool
            {
                const char* l = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
                for (int i = 0; i < 32; i++)
                {
                    if (l[i] == c) return true;
                }
                return false;
            };
        if (contain(c1) && contain(c2) && contain(c3) && c1 != c2 && c2 != c3 && c1 != c3)
        {
            return BinaryParams::from_base64(c1, c2, c3);
        }
        else
        {
            std::cout << "invalid operation" << std::endl;
            return std::nullopt;
        }
    }
    if (str[0] == '4')
    {
        std::string path_str = str.substr(2);
        auto writeable = [](const std::string& str)->bool
            {
                fs::path p{ str };
                std::error_code ec;
                if (!fs::is_regular_file(p)) return false;
                auto perms = fs::status(p, ec).permissions();
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
    std::cout << "invalid operation" << std::endl;
    return std::nullopt;
}
using dog_torch::crypto::hash::Generator;
namespace hash = dog_torch::crypto::hash;
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
        std::cout << std::format("{}:{},", k, dog_torch::crypto::get_type_name(v));
        if (v == dog_torch::crypto::ParamType::Bool)
        {
            auto arg = input_bool();
            if (!arg.has_value()) return nullptr;
            tar_params[k] = arg.value();
        }
        else if (v == dog_torch::crypto::ParamType::UInt64)
        {
            auto arg = input_uint64();
            if (!arg.has_value()) return nullptr;
            tar_params[k] = arg.value();
        }
        else if (v == dog_torch::crypto::ParamType::String)
        {
            auto arg = input_string();
            tar_params[k] = arg;
        }
        else if (v == dog_torch::crypto::ParamType::Binary)
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
    clear_cmd();
    if (data.value().index() == 0)
    {
        data = gen->calculate(std::get<0>(data.value()));
        auto tar_str = arr.fmt_BinaryData(std::get<0>(data.value()));
        using dog_torch::serialize::type_fmt_string;
        std::cout << "=====input=====" << "\n";
        std::cout << str << "\n";
        std::cout << "=====operate=====" << "\n";
        std::cout << std::format("{}-[{}]->{}", type_fmt_string(static_cast<serializeType>(type)), gen->fmt_string(), arr.fmt_string()) << "\n";
        std::cout << "=====output=====" << "\n";
        std::cout << tar_str << "\n";
    }
    else
    {
        auto fpath = std::get<1>(data.value());
        auto result = pool.add_task(
            [gen](dog_torch::async::thread::PauseableChannel& pc, fs::path path)
            {
                pc.param("path") = path.string();
                std::ifstream ifs(path, std::ios::binary);
                uint64_t size = fs::file_size(path);
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
void task_manage(
    PausedThreadPool& pool, 
    std::unordered_map<uint64_t, HashResult>& hash_results, 
    std::vector<std::pair<uint64_t, PauseableDetail>>& task_results
)
{
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
                std::cout << " =====output=====\n";
                std::cout << future.get_binary_str() << "\n";
                std::cout << "}\n";
            }
        }
        std::cout.flush();
        std::cout << "=====tasks deatil=====" << "\n";
        for (auto& detail : details)
        {
            std::cout << "{" << "\n";
            std::cout << std::format("id: {}\n", detail.task_id);
            std::cout << " =====input=====\n";
            std::cout << hash_results[detail.task_id].get_input_path_str() << "\n";
            std::cout << " =====operate=====\n";
            std::cout << std::format("file-[{}]->{}\n", std::any_cast<std::string>(detail.params.at("config_str")), hash_results[detail.task_id].output_type.fmt_string());
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



void using_mode()
{

    PausedThreadPool pool{ 1 };
    pool.start();

    std::unordered_map<uint64_t, HashResult> hash_results;
    std::vector<std::pair<uint64_t, PauseableDetail>> task_results;
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
            else if (op == 5)
            {
                task_manage(pool, hash_results, task_results);
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