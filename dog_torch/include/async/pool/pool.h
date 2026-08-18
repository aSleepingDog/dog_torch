#pragma once
#include "export.h"

#include <mutex>
#include <vector>
#include <string>
#include <chrono>
#include <future>
#include <iostream>
#include <shared_mutex>

#include "utils/exception.h"
#include "async/container.h"
#include "async/thread/async_thread_base.h"
#include "async/async_base.h"

namespace dog_torch::async::pool
{
	template<typename T,typename Alloc = std::allocator<T>>
	using VectorMove = dog_torch::async::container::VectorMove<T, Alloc>;
	template<typename T, typename Alloc = std::allocator<T>>
	using DequeMove = dog_torch::async::container::DequeMove<T, Alloc>;

	using dog_torch::async::thread::PauseableChannel;
	using dog_torch::async::thread::PauseableDetail;
	using dog_torch::async::thread::PauseFunc;
	template<typename T>
	struct SharedResult;

	/**
	 * @brief Result of a task in the PausedThreadPool.
	 * @brief 可暂停线程池(PausedThreadPool)的异步任务结果
	 */
	template<typename T>
	struct Result
	{
		uint64_t task_id;
		std::future<T> future;

		/**
		 * @param tid The task ID. 
		 * @param tid 任务ID
		 * 
		 * @param f The future associated with the task.
		 * @param f 异步任务的未来体的亡值
		 */
		Result(uint64_t tid, std::future<T>&& f) : task_id(tid), future(std::move(f)) {}
		/**
		 * @brief Share the result with other tasks.
		 * @brief 将此类的结果共享
		 * 
		 * @warning this future will be invalid after this operation.
		 * @warning 此操作后此类的future将失效
		 * 
		 * @return A shared result object.
		 * @return 共享结果对象
		 */
		SharedResult<T> share()
		{
			return { task_id, future.share() };
		}
	};

	/**
	 * @brief Shared result of a task in the PausedThreadPool.
	 * @brief 可暂停线程池(PausedThreadPool)的共享异步任务结果
	 */
	template<typename T>
	struct SharedResult
	{
		uint64_t task_id;
		std::shared_future<T> future;

		/**
		 * @param tid The task ID.
		 * @param tid 任务ID
		 * 
		 * @param f The shared future associated with the task.
		 * @param f 共享的未来体的亡值
		 */
		SharedResult(uint64_t tid, std::shared_future<T>&& f) : task_id(tid), future(std::move(f)) {};
	};


	/**
	 * @brief A thread pool that supports pausing and resuming tasks.
	 * @brief 可暂停线程池 支持任务的暂停和恢复
	 */
	class CPP_API PausedThreadPool
	{
	private:
		/**
		 * @brief A worker thread in the PausedThreadPool.
		 * @brief 可暂停线程池中的工作线程
		 */
		class Worker
		{
		public:
			PauseableChannel pc;
			std::jthread thread;
			uint64_t task_id = 0;

			Worker() = default;

			Worker(const Worker&) = delete;
			Worker& operator=(const Worker&) = delete;

			Worker(Worker&& other) noexcept;
			Worker& operator=(Worker&& other) noexcept;

			~Worker();
		};

		/**
		 * @brief A task in the PausedThreadPool.
		 * @brief 可暂停线程池中的任务
		 */
		class Task
		{
		public:
			/**
			 * @brief The ID of the task.
			 * @brief 任务ID
			 */
			uint64_t id = 0;
			/**
			 * @brief The function to be executed by the task.
			 * @brief 任务执行的函数
			 */
			std::function<void(PauseableChannel&)> func;
			Task() = default;
			Task(std::function<void(PauseableChannel&)>&& pfunc, uint64_t pid)
				: func(std::move(pfunc)), id(pid) {}
		};

		std::mutex mutex_;
		std::unique_ptr<std::condition_variable> condition_variable_ = std::make_unique<std::condition_variable>();
		std::atomic<Status> status_ = Status::Ready;
		std::atomic<uint64_t> task_next_id_ = 1;
		std::atomic<uint64_t> worker_count_ = 0;
		VectorMove<Worker> workers_;
		DequeMove<Task> tasks_;
	public:
		PausedThreadPool(uint64_t count);
		~PausedThreadPool();

		static void work(PausedThreadPool& self, Worker& worker);

		void start();

		void resize(uint64_t count);

		void wait_stop();
		void pause_all();
		void stop_all();
		std::vector<PauseableDetail> get_tasks_detail();

		bool pause(uint64_t task_id);
		bool resume(uint64_t task_id);
		bool cancel(uint64_t task_id);
		bool stop(uint64_t task_id);

		template<typename Func, typename... Args>
			requires PauseFunc<Func, Args...>
		auto add_task(Func&& func, Args&&... args) -> Result<decltype(func(std::declval<PauseableChannel&>(), std::forward<Args>(args)...))>
		{
			using ResType = decltype(func(std::declval<PauseableChannel&>(), std::forward<Args>(args)...));
			using promRes = std::promise<ResType>;

			std::shared_ptr<promRes> prom = std::make_shared<promRes>();
			auto func_bind = std::bind(func, std::placeholders::_1, std::forward<Args>(args)...);
			std::function<void(PauseableChannel&)> task;
			if constexpr (std::is_void_v<ResType>)
			{
				auto doing = [func_bind, prom](PauseableChannel& pc)->void
					{
						try
						{
							func_bind(pc);
							prom->set_value();
						}
						catch (std::exception& e)
						{
							prom->set_exception(std::make_exception_ptr(e));
						}
					};
				task = std::move(doing);
			}
			else
			{
				auto doing = [func_bind, prom](PauseableChannel& pc)->void
					{
						try
						{
							prom->set_value(func_bind(pc));
						}
						catch (std::exception& e)
						{
							prom->set_exception(std::make_exception_ptr(e));
						}
					};
				task = std::move(doing);
			}
			std::unique_lock lock(this->mutex_);
			uint64_t task_id = this->task_next_id_++;
			this->tasks_.emplace_back({ std::move(task),  task_id });
			condition_variable_->notify_one();
			return Result{ task_id, std::move(prom->get_future()) };
		}

		template<typename Func, typename... Args>
			requires PauseFunc<Func, Args...>
		auto add_task_pass(Func&& func, Args&&... args) -> uint64_t
		{
			using ResType = decltype(func(std::declval<PauseableChannel&>(), std::forward<Args>(args)...));
			auto func_bind = std::bind(func, std::placeholders::_1, std::forward<Args>(args)...);
			std::function<void(PauseableChannel&)> task;
			auto doing = [func_bind](PauseableChannel& pc)->void
				{
					func_bind(pc);
				};
			task = std::move(doing);
			std::unique_lock lock(this->mutex_);
			uint64_t task_id = this->task_next_id_++;
			this->tasks_.emplace_back({ std::move(task),  task_id });
			condition_variable_->notify_one();
			return task_id;
		}
	};
}