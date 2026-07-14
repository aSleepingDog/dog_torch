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

	class DOG_TORCH_API PausedThreadPool
	{
	private:
		class Worker
		{
		public:
			PauseableChannel pc;
			std::jthread thread;
			uint64_t task_id = 0;

			Worker() = default;

			Worker(const Worker&) = delete;
			Worker& operator=(const Worker&) = delete;

			Worker(Worker&& other) noexcept
			{
				this->pc = std::move(other.pc);
				this->thread = std::move(other.thread);
				this->task_id = other.task_id;
			};
			Worker& operator=(Worker&& other) noexcept
			{
				this->pc = std::move(other.pc);
				this->thread = std::move(other.thread);
				this->task_id = other.task_id;
				return *this;
			}
		};

		class Task
		{
		public:
			uint64_t id = 0;
			std::function<void(PauseableChannel&)> func;
			Task() = default;
			Task(std::function<void(PauseableChannel&)>&& pfunc, uint64_t pid)
				: func(std::move(pfunc)), id(pid) {}
		};

		std::mutex mutex_;
		std::unique_ptr<std::condition_variable> condition_variable_ = std::make_unique<std::condition_variable>();
		std::atomic<Status> status_ = Status::Ready;
		std::atomic<uint64_t> task_next_id_ = 1;
		std::atomic<uint64_t> worker_count_;
		VectorMove<Worker> workers_;
		DequeMove<Task> tasks_;
	public:
		PausedThreadPool(uint64_t count)
		{
			worker_count_.store(count);
			workers_.reserve(count);
		}
		~PausedThreadPool()
		{
			stop_all();
		}

		void start()
		{
			auto work = [this](Worker& self_worker) -> void
			{
				while (this->status_.load() != Status::Stopped)
				{
					Task task;
					{
					std::unique_lock<std::mutex> lock(this->mutex_);
					this->condition_variable_->wait(lock, [this, &self_worker]()->bool
						{
							return this->status_ == Status::Stopped || this->status_ == Status::Blocked || !this->tasks_.empty();
						});
					if (this->status_ == Status::Stopped) return;
					task = this->tasks_.take_front();
					}
					self_worker.task_id = task.id;
					try
					{
						task.func(self_worker.pc);
					}
					catch (const std::exception& e)
					{
						std::cout << e.what() << std::endl;
					}
					self_worker.pc.stop();
					self_worker.pc.reset();
				}
			};
			workers_.doing([work, n = this->worker_count_.load()](std::vector<Worker>& vec)->void
				{
					vec.resize(n);
					for (auto& worker : vec)
					{
						worker.thread = std::jthread(work, std::ref(worker));
					}
				}
			);
		}

		void wait_stop()
		{
			while (true)
			{
				if (tasks_.empty()) break;
				std::this_thread::yield();
			}
		}
		void pause_all()
		{
			status_.store(Status::Blocked);
			workers_.doing([](std::vector<Worker>& workers)->void
				{
					for (auto& worker : workers)
					{
						worker.pc.pause();
					}
				});
		}
		void stop_all()
		{
			status_.store(Status::Stopped);
			this->condition_variable_->notify_all();
			auto waiting = [](std::vector<Worker>& workers)-> void
				{
					for (auto& worker : workers)
					{
						worker.pc.stop();
						worker.thread.join();
					}
				};
			workers_.doing(waiting);
		}
		std::vector<std::pair<uint64_t, PauseableDetail>> get_tasks_detail()
		{
			std::vector<std::pair<uint64_t, PauseableDetail>> details;
			auto get_detail = [&details](std::vector<Worker>& workers)-> void
				{
					for (auto& worker : workers)
					{
						if (worker.task_id != 0)
						{
							std::pair<uint64_t, PauseableDetail> item(
								worker.task_id, worker.pc.to_detail()
							);
							details.emplace_back(item);
							if (worker.pc.status() == Status::Stopped)
							{
								worker.task_id = 0;
							}
						}
					}
				};
			workers_.doing(get_detail);
			return details;
		}

		bool pause(uint64_t task_id)
		{
			bool result = false;
			workers_.doing([&result, &task_id](std::vector<Worker>& workers)->void
				{
					for (auto& worker : workers)
					{
						if (worker.task_id == task_id)
						{
							worker.pc.pause();
							result = true;
							break;
						}
					}
				});
			return result;
		}
		bool resume(uint64_t task_id)
		{
			bool result = false;
			workers_.doing([&result, &task_id](std::vector<Worker>& workers)->void
				{
					for (auto& worker : workers)
					{
						if (worker.task_id == task_id)
						{
							worker.pc.resume();
							result = true;
							break;
						}
					}
				});
			return result;
		}
		bool stop(uint64_t task_id)
		{
			bool result = false;
			workers_.doing([&result, &task_id](std::vector<Worker>& workers)->void
				{
					for (auto& worker : workers)
					{
						if (worker.task_id == task_id)
						{
							worker.pc.stop();
							result = true;
							break;
						}
					}
				});
			return result;
		}

		template<typename Func, typename... Args>
			requires PauseFunc<Func, Args...>
		auto add_task(Func&& func, Args&&... args) -> std::pair<uint64_t, std::future<decltype(func(std::declval<PauseableChannel&>(), std::forward<Args>(args)...))>>
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
			return std::pair{ task_id, std::move(prom->get_future()) };
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
			return task_id;
		}
	};
}