#pragma once
#include "export.h"

#include <mutex>
#include <vector>
#include <string>
#include <chrono>
#include <unordered_map>
#include <condition_variable>
#include <any>

#include "math/number.h"
#include "utils/exception.h"
#include "async/async_base.h"

namespace dog_torch::async::thread
{
	/**
	 * @brief 任务详情
	 * @brief be used for returning task status
	 * @brief 用于返回任务的状态
	 */
	struct CPP_API PauseableDetail
	{
		/**
		 * 任务id
		 */
		uint64_t task_id = 0;
		/**
		 * 任务状态
		 */
		Status status;
		/**
		 * 任务进度(范围由任务指定)
		 * 有效值[0.0, 1.0]
		 */
		double progress;
		/**
		 * 任务持续时间(ms)
		 */
		uint64_t time;
		/**
		 * 任务额外参数
		 */
		std::unordered_map<std::string, std::any> params;
	};

	/**
	 * @brief 线程控制块
	 * @brief be used for controlling thread
	 * @brief 用于控制线程的暂停、恢复、停止等操作
	 */
	class CPP_API PauseableChannel
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
		/**
		 * @brief Construct a new Pauseable Channel object
		 * @brief 创建一个线程控制块
		 * @param need_clock 是否需要时钟
		 */
		PauseableChannel(bool need_clock = true, const std::unordered_map<std::string, std::any>& param = {});//Create -> Ready

		PauseableChannel(const PauseableChannel&) = delete;
		PauseableChannel& operator=(const PauseableChannel&) = delete;
		PauseableChannel(PauseableChannel&& other) noexcept;
		PauseableChannel& operator=(PauseableChannel&& other) noexcept;

		/**
		 * @brief 获取任务id
		 * @brief get task id
		 * @return Status
		 * @return 任务状态
		 */
		Status status() const;
		/**
		 * @brief start task
		 * @brief 开始任务
		 */
		void start();//Ready -> Running
		/**
		 * @brief pause task
		 * @brief 暂停任务
		 */
		void pause();//Running -> Blocked
		/**
		 * @brief check task status
		 * @brief 检查任务状态
		 */
		bool check_status();
		/**
		 * @brief check task status
		 * @brief 检查任务状态
		 */
		void resume();//Blocked -> Running
		/**
		 * @brief stop task
		 * @brief 停止任务
		 */
		void stop();//Running|Blocked -> Stopped
		/**
		 * @brief cancel task
		 * @brief 取消任务
		 */
		void cancel();//Running|Blocked -> Stopped
		/**
		 * @brief reset task
		 * @brief 重置任务
		 */
		void reset();//Stopped -> Ready
		/**
		 * @brief check task is canceled
		 * @brief 检查任务是否被取消
		 */
		bool is_cancel();
		/**
		 * @brief get task detail
		 * @brief 获得任务详情
		 * @return PauseableDetail
		 * @return 任务详情
		 */
		PauseableDetail to_detail();
		/**
		 * @brief set task progress
		 * @brief 设置任务进度
		 */
		void set_progress(double progress);
		/**
		 * @brief add task progress
		 * @brief 增加任务进度
		 */
		void add_progress(double progress);
		/**
		 * @brief get task extra params
		 * @brief 获取任务额外参数
		 */
		std::unordered_map<std::string, std::any>& params();
		const std::unordered_map<std::string, std::any>& params() const;
		/**
		 * @brief get task extra param
		 * @brief 获取任务额外参数
		 * @param key 参数名
		 * @param key name
		 * @return std::any 参数值
		 * @return std::any value
		 */
		std::any& param(const std::string& key);
		/**
		 * @brief get task extra param
		 * @brief 获取任务额外参数
		 * @param key 参数名
		 * @param key name
		 * @return std::any 参数值
		 * @return std::any value
		 */
		const std::any& param(const std::string& key) const;
		/**
		 * @brief get task progress
		 * @brief 获取任务进度
		 */
		double get_progress();
	};

	/**
	 * @brief concept for function with PauseableChannel as first arg
	 * @brief 使用了线程控制块的方法概念
	 */
	template<typename Func, typename... Args>
	concept PauseFunc = requires(Func f, PauseableChannel & pc, Args&&... args)
	{
		f(pc, std::forward<Args>(args)...);
	};
}