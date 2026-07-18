#pragma once
#include "export.h"

#include <mutex>
#include <vector>
#include <string>
#include <chrono>
#include <unordered_map>
#include <any>

#include "math/number.h"
#include "utils/exception.h"
#include "async/async_base.h"

namespace dog_torch::async::thread
{
	struct DOG_TORCH_API PauseableDetail
	{
		uint64_t task_id = 0;
		Status status;
		double progress;
		uint64_t time;
		std::unordered_map<std::string, std::any> params;
	};

	class DOG_TORCH_API PauseableChannel
	{
	private:
		std::mutex mutex_;
		std::unique_ptr<std::condition_variable> condition_variable_;
		std::atomic<Status> status_ = Status::Ready;
		std::atomic<double> progress_ = 0;
		std::atomic<bool> is_failed_ = false;
		std::unordered_map<std::string, std::any> params_;
		std::unique_ptr<Clock<std::chrono::milliseconds>> clock_ = nullptr;
	public:
		PauseableChannel(bool need_clock = true, const std::unordered_map<std::string, std::any>& param = {});//Create -> Ready

		PauseableChannel(const PauseableChannel&) = delete;
		PauseableChannel& operator=(const PauseableChannel&) = delete;
		PauseableChannel(PauseableChannel&& other) noexcept;
		PauseableChannel& operator=(PauseableChannel&& other) noexcept;

		Status status() const;
		void start();//Ready -> Running
		void pause();//Running -> Blocked
		bool check_status();
		void resume();//Blocked -> Running
		void stop();//Running|Blocked -> Stopped
		void cancel();//Running|Blocked -> Stopped
		void reset();//Stopped -> Ready
		bool is_cancel();
		PauseableDetail to_detail();
		void set_progress(double progress);
		void add_progress(double progress);
		std::any& param(const std::string& key);
		const std::any& param(const std::string& key) const;
		double get_progress();
	};

	/**
	* 使用了线程控制块的方法概念
	*/
	template<typename Func, typename... Args>
	concept PauseFunc = requires(Func f, PauseableChannel & pc, Args&&... args)
	{
		f(pc, std::forward<Args>(args)...);
	};
}