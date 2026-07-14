#pragma once
#include "export.h"

#include <mutex>
#include <vector>
#include <string>
#include <chrono>

#include "math/number.h"
#include "utils/exception.h"
#include "async/async_base.h"

namespace dog_torch::async::thread
{
	struct DOG_TORCH_API PauseableDetail
	{
		Status status;
		double progress;
		uint64_t time;
	};

	class DOG_TORCH_API PauseableChannel
	{
	private:
		std::mutex mutex_;
		std::unique_ptr<std::condition_variable> condition_variable_;
		std::atomic<Status> status_ = Status::Ready;
		std::atomic<double> progress_ = 0;
		std::unique_ptr<Clock<std::chrono::milliseconds>> clock_ = nullptr;
	public:
		PauseableChannel(bool need_clock = true);//Create -> Ready

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
		void reset();//Stopped -> Ready
		PauseableDetail to_detail();
		void set_progress(double progress);
		void add_progress(double progress);
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