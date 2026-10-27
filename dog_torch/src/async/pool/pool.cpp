#include "async/pool/pool.h"

namespace NSROOT = dog_torch::async::pool;

NSROOT::PausedThreadPool::Worker::Worker(Worker&& other) noexcept
{
	this->pc = std::move(other.pc);
	this->thread = std::move(other.thread);
	this->task_id = other.task_id;
};
NSROOT::PausedThreadPool::Worker& NSROOT::PausedThreadPool::Worker::operator=(Worker&& other) noexcept
{
	if (this == &other) return *this;
	this->pc = std::move(other.pc);
	this->thread = std::move(other.thread);
	this->task_id = other.task_id;
	return *this;
}
NSROOT::PausedThreadPool::Worker::~Worker()
{
	pc.stop();
	if (this->thread.joinable()) this->thread.join();
}
NSROOT::PausedThreadPool::PausedThreadPool(uint64_t count)
{
	worker_count_.store(count);
	workers_.reserve(count);
}
NSROOT::PausedThreadPool::~PausedThreadPool()
{
	stop_all();
}
void NSROOT::PausedThreadPool::work(PausedThreadPool& self, Worker& self_worker)
{
	while (self.status_.load() != Status::Stopped)
	{
		Task task;
		{
			std::unique_lock<std::mutex> lock(self.mutex_);
			if(self.tasks_.size() == 0)
			{
				self.condition_variable_->wait(lock, [&self, &self_worker]()->bool
					{
						return self.status_ == Status::Stopped || self.status_ == Status::Blocked || !self.tasks_.empty();
					});
				if (self.status_ == Status::Stopped) return;
			}
			task = self.tasks_.take_front();
		}
		self_worker.task_id = task.id;
		self_worker.pc.params() = std::move(task.params);
		try
		{
			task.func(self_worker.pc);
		}
		catch (const std::exception& e)
		{
			std::cout << e.what() << std::endl;
		}
    	self_worker.pc.set_progress(1.0);
    	self_worker.pc.stop();
		auto detail = self_worker.pc.to_detail();
		detail.task_id = self_worker.task_id;	
		self.finished_tasks_.push_back(std::move(detail));
		self_worker.pc.stop();
		self_worker.pc.reset();
		self_worker.task_id = 0;
	}
};
void NSROOT::PausedThreadPool::start()
{
	workers_.doing([this, n = this->worker_count_.load()](std::vector<Worker>& vec)->void
		{
			vec.resize(n);
			for (auto& worker : vec)
			{
				worker.thread = std::jthread(NSROOT::PausedThreadPool::work, std::ref(*this), std::ref(worker));
			}
		}
	);
}
void NSROOT::PausedThreadPool::resize(uint64_t count)
{
	workers_.doing([this, count](std::vector<Worker>& vec)->void
		{
			uint64_t now = this->worker_count_.load();
			vec.resize(count);
			if (count > now)
			{
				for (uint64_t i = now; i < count; ++i)
				{
					vec[i].thread = std::jthread(NSROOT::PausedThreadPool::work, std::ref(*this), std::ref(vec[i]));
				}
			}
		});
	worker_count_.store(count);
}
void NSROOT::PausedThreadPool::wait_stop()
{
    std::unique_lock lock(mutex_);
	condition_variable_->wait(lock, [this]() -> bool
		{
			if (!tasks_.empty())
			{
				return false;
			}
			bool is_all_stop = true;
			this->workers_.doing([&is_all_stop](std::vector<Worker>& workers)->void
				{
					for (auto& worker : workers)
					{
						if (worker.pc.status() != Status::Stopped && worker.pc.status() != Status::Ready)
						{
							is_all_stop = false;
						}
					}
				}
			);
			return is_all_stop;
		}
	);
}
void NSROOT::PausedThreadPool::pause_all()
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
void NSROOT::PausedThreadPool::stop_all()
{
	status_.store(Status::Stopped);
	this->tasks_.clear();
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
using dog_torch::async::thread::PauseableDetail;
std::vector<PauseableDetail> NSROOT::PausedThreadPool::get_tasks_detail()
{
	std::vector<PauseableDetail> details;
	auto get_detail = [&details](std::vector<Worker>& workers)-> void
		{
			for (auto& worker : workers)
			{
				if (worker.task_id != 0)
				{
					PauseableDetail item = worker.pc.to_detail();
					item.task_id = worker.task_id;
					details.push_back(item);
					if (worker.pc.status() == Status::Stopped)
					{
						worker.task_id = 0;
					}
				}
			}
		};
	workers_.doing(get_detail);
	auto get_detail0 = [&details](std::deque<Task>& tasks)-> void
		{
			for (auto& task : tasks)
			{
				PauseableDetail item;
				item.task_id = task.id;
				item.status = Status::Created;
				item.progress = 0.0;
				item.time = 0;
				item.params = task.params;
				details.push_back(item);
			}
		};
	this->tasks_.doing(get_detail0);
	while (!this->finished_tasks_.empty())
	{
		details.push_back(this->finished_tasks_.take_front());
	}
	return details;
}

bool NSROOT::PausedThreadPool::pause(uint64_t task_id)
{
	bool result = false;
	workers_.doing([&result, &task_id](std::vector<Worker>& workers)->void
		{
			for (auto& worker : workers)
			{
				if (worker.task_id == task_id)
				{
					if (worker.pc.status() != Status::Running) break;
					worker.pc.pause();
					result = true;
					break;
				}
			}
		});
	return result;
}
bool NSROOT::PausedThreadPool::resume(uint64_t task_id)
{
	bool result = false;
	workers_.doing([&result, &task_id](std::vector<Worker>& workers)->void
		{
			for (auto& worker : workers)
			{
				if (worker.task_id == task_id)
				{
					if (worker.pc.status() != Status::Blocked) break;
					worker.pc.resume();
					result = true;
					break;
				}
			}
		});
	return result;
}
bool NSROOT::PausedThreadPool::cancel(uint64_t task_id)
{
	bool result = false;
	this->tasks_.doing([&result,&task_id](std::deque<Task>& tasks)->void
		{
			for(auto it = tasks.begin();it != tasks.end();it++)
			{
				if(it->id == task_id)
				{
					tasks.erase(it);
					result = true;
					break;
				}
			}
		}
	);
	if(!result)
	{
		workers_.doing([&result, &task_id](std::vector<Worker>& workers)->void
		{
			for (auto& worker : workers)
			{
				if (worker.task_id == task_id)
				{
					if (worker.pc.status() != Status::Running && worker.pc.status() != Status::Blocked) break;
					worker.pc.cancel();
					result = true;
					break;
				}
			}
		});
	}
	return result;
}
bool NSROOT::PausedThreadPool::stop(uint64_t task_id)
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