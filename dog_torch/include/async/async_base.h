#pragma once
#include "export.h"
#include <iostream>
#include <vector>
#include <string>
#include <chrono>

#include "math/number.h"
#include "utils/exception.h"

namespace dog_torch::async
{
	/**
	 * ```
	 *           (init)    
	 * Created --> Ready -[start]-> Running -[stop]-> Stopped -[reset]-> Ready
	 *                          pause | ^
	 *                                v | resume
	 *                              Blocked
	 * ```
	 */
	enum class CPP_API Status : uint8_t
	{
		Created = 0,
		Ready = 1,
		Running = 2,
		Blocked = 3,
		Stopped = 4
	};

	/**
	 * @brief Convert status to string
	 * @brief 将状态转换为字符串
	 * @param status 状态
	 * @return std::string
	 */
	CPP_API std::string status_to_string(Status status);

	/**
	 * @brief concept for std::chrono time unit
	 * @brief 将字符串转换为状态
	 */
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

	/**
	 * @brief TimeUnit enum
	 * @brief 时间单位枚举
	 */
	enum class CPP_API TimeUnit : uint8_t
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


	/**
	 * @brief Convert single unit to multiple units
	 * @brief convert<TimeUnit::Seconds, TimeUnit::Hours>(5264) => {1,27,44} => 01:27:44
	 * @brief 将单一时间单位转换成各个单位的时间
	 * @tparam S first arg unit
	 * @tparam S 第一个参数的时间单位
	 * @tparam E biggest unit to convert
	 * @tparam E 最大转换的时间单位
	 * @param value time for convert
	 * @param value 需要转换的时间值
	 * @return std::array<uint64_t, (static_cast<uint64_t>(E) + 1 - static_cast<uint64_t>(S))> result
	 * @return std::array<uint64_t, (static_cast<uint64_t>(E) + 1 - static_cast<uint64_t>(S))> 转换后的结果
	 */
	template<TimeUnit S, TimeUnit E = TimeUnit::Weeks> 
	std::array<uint64_t, (static_cast<uint64_t>(E) + 1 - static_cast<uint64_t>(S))> convert(uint64_t value)
	{
		std::array<uint64_t, 7> time_unit_table = { 1000,1000,1000,60,60,24,7 };
        std::array<uint64_t, (static_cast<uint64_t>(E) + 1 - static_cast<uint64_t>(S))> result;
		for (uint64_t i = static_cast<uint64_t>(S); i <= static_cast<uint64_t>(E); ++i)
		{
			result[i - static_cast<uint64_t>(S)] = value % time_unit_table[i];
			value /= time_unit_table[i - static_cast<uint64_t>(S)];
		}
		return result;
	}

	/**
	 * @brief 计时器
	 * @tparam T std::chrono time unit
	 * @tparam T std::chrono 时间单位
	 */
	template<is_std_duration T>
	class CPP_API Clock
	{
	private:
		Status stage_ = Status::Ready;
		std::chrono::steady_clock::time_point start_time_;
		std::chrono::steady_clock::time_point end_time_;
		uint64_t total_ = 0;
	public:
		/**
		 * @brief Create a clock
		 * @brief 创建一个计时器
		 */
		Clock() {};//Create => Ready
		/**
		 * @brief Get the current state of the clock
		 * @brief 获取计时器的当前状态
		 * @return Status
		 * @return 计时器的当前状态
		 */
		Status state() const
		{
			return this->stage_;
		}
		/**
		 * @brief start the clock
		 * @brief 启动计时器
		 */
		void start() //Ready => Running
		{
			if (this->stage_ != Status::Ready) return;
			this->start_time_ = std::chrono::steady_clock::now();
			this->stage_ = Status::Running;
		}
		/**
		 * @brief pause the clock
		 * @brief 暂停计时器
		 */
		void pause() //Running => Blocked
		{
			if (this->stage_ != Status::Running) return;
			this->end_time_ = std::chrono::steady_clock::now();
			this->total_ += std::chrono::duration_cast<T>(this->end_time_ - this->start_time_).count();
			this->stage_ = Status::Blocked;
		}
		/**
		 * @brief resume the clock
		 * @brief 恢复计时器
		 */
		void resume() //Blocked => Running
		{
			if (this->stage_ != Status::Blocked) return;
			this->start_time_ = std::chrono::steady_clock::now();
			this->stage_ = Status::Running;
		}
		/**
		 * @brief stop the clock
		 * @brief 停止计时器
		 */
		void stop() //Running | Blocked => Stopped
		{
			if (this->stage_ != Status::Running && this->stage_ != Status::Blocked) return;
			this->end_time_ = std::chrono::steady_clock::now();
			this->total_ += std::chrono::duration_cast<T>(this->end_time_ - this->start_time_).count();
			this->stage_ = Status::Stopped;
		}
		/**
		 * @brief reset the clock
		 * @brief 重置计时器
		 */
		void reset()//Running | Blocked => Stopped => Ready
		{
			if (this->stage_ != Status::Stopped) return;
			this->total_ = 0;
			this->stage_ = Status::Ready;
		}
		/**
		 * @brief get the elapsed time
		 * @brief 获取经过的时间
		 */
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


	/**
	 * @brief 自动计时器
	 */
	template<is_std_duration T>
	class AutoClock
	{
	private:
		uint64_t* total_ = nullptr;
		std::chrono::steady_clock::time_point start_time_;
		std::chrono::steady_clock::time_point end_time_;
	public:
		/**
		 * @brief Create a auto clock
		 * @brief 创建一个自动计时器
		 * @param total pointer to the total time
		 * @param total 指向总时间的指针
		 */
		AutoClock(uint64_t* total = nullptr)
		{
			this->total_ = total;
			this->start_time_ = std::chrono::steady_clock::now();
		}
		/**
		 * @brief print Elapsed before Destroy the AutoClock
		 * @brief 打印经过的时间后销毁自动计时器 
		 */
		~AutoClock()
		{
			this->end_time_ = std::chrono::steady_clock::now();
			if (this->total_ != nullptr) *this->total_ += std::chrono::duration_cast<T>(this->end_time_ - this->start_time_).count();
			std::cout << "Elapsed: " << std::chrono::duration_cast<T>(this->end_time_ - this->start_time_).count() << std::endl;
		}
	};
}