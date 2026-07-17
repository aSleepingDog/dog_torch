#pragma once
#include "export.h"

#include <vector>
#include <string>
#include <chrono>

#include "math/number.h"
#include "utils/exception.h"

namespace dog_torch::async
{
	/*           (init)    
	* Created --> Ready -[start]-> Running -[stop]-> Stopped -[reset]-> Ready
	*                          pause | ^
	*                                v | resume
	*                              Blocked
	*/
	enum class DOG_TORCH_API Status : uint8_t
	{
		Created = 0,
		Ready = 1,
		Running = 2,
		Blocked = 3,
		Stopped = 4
	};

	DOG_TORCH_API std::string status_to_string(Status status);

	template<typename Dur>
	concept is_std_duration =
		std::is_same_v<Dur, std::chrono::nanoseconds> ||
		std::is_same_v<Dur, std::chrono::microseconds> ||
		std::is_same_v<Dur, std::chrono::milliseconds> ||
		std::is_same_v<Dur, std::chrono::seconds> ||
		std::is_same_v<Dur, std::chrono::minutes> ||
		std::is_same_v<Dur, std::chrono::hours> ||
		std::is_same_v<Dur, std::chrono::days> ||
		std::is_same_v<Dur, std::chrono::weeks>;

	enum class DOG_TORCH_API TimeUnit : uint8_t
	{
		Nanoseconds = 0,
		Microseconds = 1,
		Milliseconds = 2,
		Seconds = 3,
		Minutes = 4,
		Hours = 5,
		Days = 6,
		Weeks = 7,
		Count = 8
	};


	template<TimeUnit S, TimeUnit E = TimeUnit::Weeks> 
	std::array<uint64_t, (static_cast<uint64_t>(E) + 1 - static_cast<uint64_t>(S))> convert(uint64_t value)
	{
		std::array<uint64_t, 7> time_unit_table = { 1000,1000,1000,60,60,24,7 };
        std::array<uint64_t, (static_cast<uint64_t>(E) + 1 - static_cast<uint64_t>(S))> result;
		for (uint64_t i = static_cast<uint64_t>(S); i <= static_cast<uint64_t>(E); ++i)
		{
			result[i - static_cast<uint64_t>(S)] = value / time_unit_table[i];
			value %= time_unit_table[i];
		}
		return result;
	}

	template<is_std_duration T>
	class DOG_TORCH_API Clock
	{
	private:
		Status stage_ = Status::Ready;
		std::chrono::steady_clock::time_point start_time_;
		std::chrono::steady_clock::time_point end_time_;
		uint64_t total_ = 0;
	public:
		Clock() {};//Create => Ready
		Status state() const
		{
			return this->stage_;
		}
		void start() //Ready => Running
		{
			if (this->stage_ != Status::Ready) return;
			this->start_time_ = std::chrono::steady_clock::now();
			this->stage_ = Status::Running;
		}
		void pause() //Running => Blocked
		{
			if (this->stage_ != Status::Running) return;
			this->end_time_ = std::chrono::steady_clock::now();
			this->total_ += std::chrono::duration_cast<T>(this->end_time_ - this->start_time_).count();
			this->stage_ = Status::Blocked;
		}
		void resume() //Blocked => Running
		{
			if (this->stage_ != Status::Blocked) return;
			this->start_time_ = std::chrono::steady_clock::now();
			this->stage_ = Status::Running;
		}
		void stop() //Running | Blocked => Stopped
		{
			if (this->stage_ != Status::Running && this->stage_ != Status::Blocked) return;
			this->end_time_ = std::chrono::steady_clock::now();
			this->total_ += std::chrono::duration_cast<T>(this->end_time_ - this->start_time_).count();
			this->stage_ = Status::Stopped;
		}
		void reset()//Running | Blocked => Stopped => Ready
		{
			if (this->stage_ != Status::Stopped) return;
			this->total_ = 0;
			this->stage_ = Status::Ready;
		}
		uint64_t elapsed() const
		{
			uint64_t temp = this->total_;
			if (this->stage_ == Status::Running)
			{
				temp += std::chrono::duration_cast<T>(std::chrono::steady_clock::now() - this->start_time_).count();
			}
			return temp;
		}
	};


	template<is_std_duration T>
	class AutoClock
	{
	private:
		uint64_t* total_ = nullptr;
		std::chrono::steady_clock::time_point start_time_;
		std::chrono::steady_clock::time_point end_time_;
	public:
		AutoClock(uint64_t* total = nullptr)
		{
			this->total_ = total;
			this->start_time_ = std::chrono::steady_clock::now();
		}
		~AutoClock()
		{
			this->end_time_ = std::chrono::steady_clock::now();
			if (this->total_ != nullptr) *this->total_ += std::chrono::duration_cast<T>(this->end_time_ - this->start_time_).count();
		}
	};
}