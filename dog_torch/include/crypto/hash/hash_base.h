#pragma once
#include "export.h"

#include <iostream>
#include <functional>

#include "serialize/serialize.h"
#include "async/thread/async_thread_base.h"
#include "crypto/crypto_base.h"

namespace dog_torch::crypto::hash
{
	using BinaryData = dog_torch::serialize::BinaryData;
	using PauseableChannel = dog_torch::async::thread::PauseableChannel;

	namespace algorithm
	{
		struct CPP_API Config
		{
			std::string name;
			std::string region;
			std::map<std::string, ParamType> params;
			Config(const std::string& name, const std::string& region, const std::map<std::string, ParamType>& params);

			Config(const Config& config);
			Config& operator=(const Config& config);
			Config(Config&& config) noexcept;
			Config& operator=(Config&& config) noexcept;
		};

		using update_func = std::function<void(const BinaryData&, BinaryData&)>;
		using trims_func = std::function<void(BinaryData&)>;

		struct CPP_API Algorithm
		{
			uint64_t effective;
			
			Algorithm(uint64_t effective);

			Algorithm(const Algorithm& algorithm);
			Algorithm& operator=(const Algorithm& algorithm);
			Algorithm(Algorithm&& algorithm) noexcept;
			Algorithm& operator=(Algorithm&& algorithm) noexcept;

			virtual ~Algorithm() = default;

			virtual Config config() const;
			virtual std::string fmt_string() const;
			
			virtual void init();
			virtual BinaryData init_data() const;
			virtual update_func get_update() const;
			virtual trims_func get_trims() const;
			virtual std::unique_ptr<Algorithm> clone() const;

			virtual uint64_t get_block_size() const;
			virtual uint64_t get_out_size() const;

			virtual bool have_next_block(uint64_t data_pos, uint64_t data_total);
			virtual BinaryData next_block(const BinaryData& data, uint64_t start, uint64_t& data_pos, uint64_t data_total);
			virtual BinaryData next_block(std::istream& data, uint64_t& data_pos, uint64_t data_total);
		};
	}

	class CPP_API Generator
	{
	private:
		std::unique_ptr<algorithm::Algorithm> algorithm_ = nullptr;
		BinaryData hash_value_;
	public:
		Generator(const std::unique_ptr<algorithm::Algorithm>& algorithm);
		Generator(std::unique_ptr<algorithm::Algorithm>&& algorithm) noexcept;
		Generator(const algorithm::Algorithm& algorithm);

		Generator(const Generator& other);
		Generator& operator=(const Generator& other);
		Generator(Generator&& other) noexcept;
		Generator& operator=(Generator&& other) noexcept;

		void init();
		BinaryData calculate(const BinaryData& source);
		BinaryData calculate(std::istream& source, uint64_t total);
		BinaryData calculate(PauseableChannel& pc, std::istream& source, uint64_t total);
		static BinaryData calculate_with(PauseableChannel& pc, Generator& self, std::istream& source, uint64_t total);
		std::string fmt_string() const;
	};
}

#ifdef SHARED
#include "async/pool/pool.h"
namespace dog_torch::async::pool
{
	using hash_stream_func = std::function<dog_torch::serialize::BinaryData(PauseableChannel&, dog_torch::crypto::hash::Generator&,std::istream&,uint64_t)>;
	template<> dog_torch::async::pool::Result<dog_torch::serialize::BinaryData> PausedThreadPool::add_task(hash_stream_func&&,dog_torch::crypto::hash::Generator&,std::istream&,uint64_t&&);
};
#endif // SHARED

#define NAMESPACE(name) dog_torch__crypto__hash__##name
#define CRYPTO_BASE(name) dog_torch__crypto__##name
#define SERIALIZE(name) dog_torch__serialize__##name
#define UTILS(name)     dog_torch__utils__##name

extern "C"
{
	using NAMESPACE(Config) = dog_torch::crypto::hash::algorithm::Config;
	using NAMESPACE(Algorithm) = dog_torch::crypto::hash::algorithm::Algorithm;
	using NAMESPACE(Generator) = dog_torch::crypto::hash::Generator;

	C_API(UTILS(CppString)*)                NAMESPACE(Config_name)                     (const LVALUE(NAMESPACE(Config)) config);
	C_API(UTILS(CppString)*)                NAMESPACE(Config_region)                   (const LVALUE(NAMESPACE(Config)) config);
	C_API(CRYPTO_BASE(ParamTypeTreeMap)*)   NAMESPACE(Config_params)                   (const LVALUE(NAMESPACE(Config)) config);

	C_API(void)                             NAMESPACE(Algorithm_delete)                (NAMESPACE(Algorithm)** self);
	C_API(UTILS(CppString)*)                NAMESPACE(Algorithm_fmt_string)            (const LVALUE(NAMESPACE(Algorithm)) self);

	C_API(NAMESPACE(Generator)*)            NAMESPACE(Generator_create_copy)           (const LVALUE(NAMESPACE(Algorithm)) alg);
	C_API(NAMESPACE(Generator)*)            NAMESPACE(Generator_create_move)           (NAMESPACE(Algorithm)** alg);
	C_API(void)                             NAMESPACE(Generator_delete)                (NAMESPACE(Generator)** self);
	C_API(UTILS(CppString)*)                NAMESPACE(Generator_fmt_string)            (const LVALUE(NAMESPACE(Generator)) self);
	C_API(SERIALIZE(BinaryData)*)           NAMESPACE(Generator_calculate_binary)      (LVALUE(NAMESPACE(Generator)) self, const LVALUE(SERIALIZE(BinaryData)) data);
	C_API(SERIALIZE(BinaryData)*)           NAMESPACE(Generator_calculate_file)        (LVALUE(UTILS(CppResultSet)) result_set, LVALUE(NAMESPACE(Generator)) self, const LVALUE(UTILS(CppString)) path);

}

#undef NAMESPACE
#undef CRYPTO_BASE
#undef SERIALIZE
#undef UTILS