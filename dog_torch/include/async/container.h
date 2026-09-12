#pragma once
#include "export.h"

#include <deque>
#include <vector>
#include <string>
#include <chrono>
#include <functional>
#include <shared_mutex>

#include "math/number.h"
#include "utils/exception.h"

namespace dog_torch::async::container
{
	/**
	* @brief 可拷贝的线程安全的std::vector封装
	*/
	template <typename T, typename Alloc = std::allocator<T>>
	class VectorCopy
	{
		using selfVec = std::vector<T, Alloc>;
		using it = std::vector<T, Alloc>::iterator;
		using doSingleFunc = std::function<void(it)>;
		using doContainerFunc = std::function<void(selfVec&)>;
		using doLoopFunc = std::function<void(selfVec&, it)>;
	private:
		mutable std::shared_mutex mutex_;
		selfVec vec_;
	public:
		VectorCopy() = default;
		~VectorCopy() = default;

		VectorCopy(const VectorCopy& other)
		{
			std::scoped_lock(mutex_, other.mutex_);
			vec_ = other.vec_;
		}
		VectorCopy& operator=(const VectorCopy& other)
		{
			std::scoped_lock(mutex_, other.mutex_);
			vec_ = other.vec_;
			return *this;
		}
		VectorCopy(VectorCopy&& other) noexcept
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			this->vec_ = std::move(other.vec_);
		}
		VectorCopy& operator=(VectorCopy&& other) noexcept
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			this->vec_ = std::move(other.vec_);
			return *this;
		}

		/**
		 * @brief get all elements and return a copy
		 * @brief 获取所有元素
		 * @returns std::vector<T> 所有元素的拷贝
		 */
		selfVec get_all() const
		{
			std::shared_lock lock(mutex_);
			return vec_;
		}
		/**
		 * @brief set all elements by copy
		 * @brief 设置所有元素
		 * @param vec std::vector<T> 要设置的元素的拷贝
		 */
		void set_all(const selfVec& vec)
		{
			std::unique_lock lock(mutex_);
			this->vec_ = vec;
		}
		/**
		 * @brief set all elements by move
		 * @brief 设置所有元素
		 * @param vec std::vector<T> 要设置的元素的移动
		 */
		void set_all(selfVec&& vec)
		{
			std::unique_lock lock(mutex_);
			this->vec_ = std::move(vec);
		}
		T at(size_t index) const
		{
			std::shared_lock lock(mutex_);
			return vec_.at(index);
		}
		T operator[](size_t index) const
		{
			std::shared_lock lock(mutex_);
			return vec_[index];
		}
		bool empty() const
		{
			std::shared_lock lock(mutex_);
			return vec_.empty();
		}
		size_t size() const
		{
			std::shared_lock lock(mutex_);
			return vec_.size();
		}
		size_t max_size() const
		{
			std::shared_lock lock(mutex_);
			return vec_.max_size();
		}
		size_t capacity() const
		{
			std::shared_lock lock(mutex_);
			return vec_.capacity();
		}
		void reserve(size_t new_cap)
		{
			std::unique_lock lock(mutex_);
			vec_.reserve(new_cap);
		}
		void shrink_to_fit()
		{
			std::unique_lock lock(mutex_);
			vec_.shrink_to_fit();
		}

		void clear()
		{
			std::unique_lock lock(mutex_);
			vec_.clear();
		}
		void insert(size_t index, const T& value)
		{
			std::unique_lock lock(mutex_);
			vec_.insert(vec_.begin() + index, value);
		}
		void erase(size_t index)
		{
			std::unique_lock lock(mutex_);
			vec_.erase(vec_.begin() + index);
		}
		void push_back(const T& value)
		{
			std::unique_lock lock(mutex_);
			vec_.push_back(value);
		}
		void pop_back()
		{
			std::unique_lock lock(mutex_);
			vec_.pop_back();
		}
		/**
		 * @brief do something with selected elements
		 * @brief 对选定的元素进行操作
		 * @param pos the position of the selected element
		 * @param pos 元素的位置
		 * @param func the function to do
		 * @param func 要做的函数
		 */
		void doing(size_t pos, doSingleFunc func)
		{
			std::unique_lock lock(mutex_);
			func(this->vec_.begin() + pos);
		}
		/**
		 * @brief do something with all container 
		 * @brief 对整个容器进行操作
		 * @param func the function to do
		 * @param func 要做的函数
		 */
		void doing(doContainerFunc func)
		{
			std::unique_lock lock(mutex_);
			func(this->vec_);
		}
		/**
		 * @brief do something with every elements
		 * @brief 对每个元素进行操作
		 * @param func the function to do
		 * @param func 要做的函数
		 */
		void doing(doLoopFunc func)
		{
			std::unique_lock lock(mutex_);
			for (auto it = vec_.begin(); it != vec_.end(); ++it)
			{
				func(vec_, it);
			}
		}

	};

	/**
	* @brief 仅可移动的线程安全的std::vector封装
	*/
	template <std::movable T, typename Alloc = std::allocator<T>>
	class VectorMove
	{
		using selfVec = std::vector<T, Alloc>;
		using it = std::vector<T, Alloc>::iterator;
		using doSingleFunc = std::function<void(it)>;
		using doContainerFunc = std::function<void(selfVec&)>;
		using doLoopFunc = std::function<void(selfVec&, it)>;
	private:
		mutable std::shared_mutex mutex_;
		selfVec vec_;
	public:
		VectorMove() = default;
		~VectorMove() = default;

		VectorMove(const VectorMove& ohter) = delete;
		VectorMove& operator=(const VectorMove& ohter) = delete;
		VectorMove(VectorMove&& other)
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			this->vec_ = std::move(other.vec_);
		}
		VectorMove& operator=(VectorMove&& other)
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			this->vec_ = std::move(other.vec_);
			return *this;
		}

		/**
		 * @brief get all elements and return a move
		 * @brief 获取所有元素的移动
		 * @returns std::vector<T> 所有元素的移动
		 */
		selfVec take_all()
		{
			std::unique_lock lock(mutex_);
			selfVec result = std::move(vec_);
			vec_.clear();
			return result;
		}
		/**
		 * @brief set all elements by move
		 * @brief 设置所有元素
		 * @param vec std::vector<T> 要设置的元素的移动
		 */
		void move_all(selfVec&& vec)
		{
			std::unique_lock lock(mutex_);
			this->vec_ = std::move(vec);
		}
		/**
		 * @brief take one element by move
		 * @brief 以移动的方式取走某个元素
		 */
		T take(size_t index)
		{
			std::unique_lock lock(mutex_);
			auto tmp = std::move(vec_[index]);
			vec_.erase(vec_.begin() + index);
			return tmp;
		}

		bool empty() const
		{
			std::shared_lock lock(mutex_);
			return vec_.empty();
		}
		size_t size() const
		{
			std::shared_lock lock(mutex_);
			return vec_.size();
		}
		size_t max_size() const
		{
			std::shared_lock lock(mutex_);
			return vec_.max_size();
		}
		size_t capacity() const
		{
			std::shared_lock lock(mutex_);
			return vec_.capacity();
		}
		void reserve(size_t new_cap)
		{
			std::unique_lock lock(mutex_);
			vec_.reserve(new_cap);
		}
		void shrink_to_fit()
		{
			std::unique_lock lock(mutex_);
			vec_.shrink_to_fit();
		}

		void clear()
		{
			std::unique_lock lock(mutex_);
			vec_.clear();
		}
		void insert(size_t index, T&& value)
		{
			std::unique_lock lock(mutex_);
			vec_.insert(vec_.begin() + index, std::move(value));
		}
		void erase(size_t index)
		{
			std::unique_lock lock(mutex_);
			vec_.erase(vec_.begin() + index);
		}
		void push_back(T&& value)
		{
			std::unique_lock lock(mutex_);
			vec_.push_back(std::move(value));
		}
		void emplace_back(T&& value)
		{
			std::unique_lock lock(mutex_);
			vec_.emplace_back(std::move(value));
		}
		void push_back(const T& value) = delete;
		void emplace_back(const T& value) = delete;
		void pop_back()
		{
			std::unique_lock lock(mutex_);
			vec_.pop_back();
		}
		/**
		 * @brief do something with selected elements
		 * @brief 对选定的元素进行操作
		 * @param pos the position of the selected element
		 * @param pos 元素的位置
		 * @param func the function to do
		 * @param func 要做的函数
		 */
		void doing(size_t pos, doSingleFunc func)
		{
			std::unique_lock lock(mutex_);
			func(this->vec_.begin() + pos);
		}
		/**
		 * @brief do something with all container
		 * @brief 对整个容器进行操作
		 * @param func the function to do
		 * @param func 要做的函数
		 */
		void doing(doContainerFunc func)
		{
			std::unique_lock lock(mutex_);
			func(vec_);
		}
		/**
		 * @brief do something with every elements
		 * @brief 对每个元素进行操作
		 * @param func the function to do
		 * @param func 要做的函数
		 */
		void doing(doLoopFunc func)
		{
			std::unique_lock lock(mutex_);
			for (auto it = vec_.begin(); it != vec_.end(); ++it)
			{
				func(vec_, it);
			}
		}
	};

	/**
	* @brief 可拷贝线程安全的std::deque封装
	*/
	template <typename T, typename Alloc = std::allocator<T>>
	class DequeCopy
	{
	private:
		using selfDqu = std::deque<T, Alloc>;
		using it = std::deque<T, Alloc>::iterator;
		using doSingleFunc = std::function<void(it)>;
		using doContainerFunc = std::function<void(selfDqu&)>;
		using doLoopFunc = std::function<void(selfDqu&, it)>;

		std::shared_mutex mutex_;
		std::deque<T, Alloc> deque_;

	public:
		DequeCopy() = default;
		~DequeCopy() = default;

		DequeCopy(const DequeCopy& other)
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			deque_ = other.deque_;
		}
		DequeCopy& operator=(const DequeCopy& other)
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			deque_ = other.deque_;
			return *this;
		}
		DequeCopy(DequeCopy&& other) noexcept
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			deque_ = std::move(other.deque_);
		}
		DequeCopy& operator=(DequeCopy&& other) noexcept
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			deque_ = std::move(other.deque_);
			return *this;
		}

		T at(size_t index)
		{
			std::shared_lock lock(mutex_);
			return deque_.at(index);
		}
		T operator[](size_t index)
		{
			std::shared_lock lock(mutex_);
			return deque_[index];
		}
		T front()
		{
			std::shared_lock lock(mutex_);
			return deque_.front();
		}
		T back()
		{
			std::shared_lock lock(mutex_);
			return deque_.back();
		}

		selfDqu get_all()
		{
			std::shared_lock lock(mutex_);
			return deque_;
		}
		void set_all(const selfDqu& other)
		{
			std::unique_lock lock(mutex_);
			deque_ = other;
		}
		void set_all(selfDqu&& other)
		{
			std::unique_lock lock(mutex_);
			deque_ = std::move(other);
		}

		bool empty()
		{
			std::shared_lock lock(mutex_);
			return deque_.empty();
		}
		size_t size()
		{
			std::shared_lock lock(mutex_);
			return deque_.size();
		}
		size_t max_size()
		{
			std::shared_lock lock(mutex_);
			return deque_.max_size();
		}
		void shrink_to_fit()
		{
			std::unique_lock lock(mutex_);
			return deque_.shrink_to_fit();
		}
		void clear()
		{
			std::unique_lock lock(mutex_);
			return deque_.clear();
		}
		void insert(size_t pos, const T& value)
		{
			std::unique_lock lock(mutex_);
			return deque_.insert(deque_.begin() + pos, std::move(value));
		}
		void emplace(size_t pos, const T& value)
		{
			std::unique_lock lock(mutex_);
			return deque_.emplace(deque_.begin() + pos, std::move(value));
		}
		void erase(size_t pos)
		{
			std::unique_lock lock(mutex_);
			return deque_.erase(deque_.begin() + pos);
		}
		void push_back(const T& value)
		{
			std::unique_lock lock(mutex_);
			deque_.push_back(value);
		}
		void emplace_back(const T& value)
		{
			std::unique_lock lock(mutex_);
			deque_.emplace_back(value);
		}
		void pop_back()
		{
			std::unique_lock lock(mutex_);
			deque_.pop_back();
		}
		void push_front(const T& value)
		{
			std::unique_lock lock(mutex_);
			deque_.push_front(value);
		}
		void emplace_front(const T& value)
		{
			std::unique_lock lock(mutex_);
			deque_.emplace_front(value);
		}
		void pop_front()
		{
			std::unique_lock lock(mutex_);
			deque_.pop_front();
		}
		/**
		 * @brief do something with selected elements
		 * @brief 对选定的元素进行操作
		 * @param pos the position of the selected element
		 * @param pos 选定元素的位置
		 * @param func the function to do
		 * @param func 要做的函数
		 */
		void doing(size_t pos, doSingleFunc func)
		{
			std::unique_lock lock(mutex_);
			func(deque_.begin() + pos);
		}
		/**
		 * @brief do something with all container
		 * @brief 对整个容器进行操作
		 * @param func the function to do
		 * @param func 要做的函数
		 */
		void doing(doContainerFunc func)
		{
			std::unique_lock lock(mutex_);
			func(deque_);
		}
		/**
		 * @brief do something with every elements
		 * @brief 对每个元素进行操作
		 * @param func the function to do
		 * @param func 要做的函数
		 */
		void doing(doLoopFunc func)
		{
			std::unique_lock lock(mutex_);
			for (auto it = deque_.begin(); it != deque_.end(); ++it)
			{
				func(deque_, it);
			}
		}
	};

	/**
	* @brief 仅可移动线程安全的std::deque封装
	*/
	template <std::movable T, typename Alloc = std::allocator<T>>
	class DequeMove
	{
	private:
		using selfDqu = std::deque<T, Alloc>;
		using it = std::deque<T, Alloc>::iterator;
		using doSingleFunc = std::function<void(it)>;
		using doContainerFunc = std::function<void(selfDqu&)>;
		using doLoopFunc = std::function<void(selfDqu&, it)>;

		std::shared_mutex mutex_;
		std::deque<T, Alloc> deque_;

	public:
		DequeMove() = default;

		DequeMove(const DequeMove& other) = delete;
		DequeMove& operator=(const DequeMove& other) = delete;
		DequeMove(DequeMove&& other) noexcept
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			deque_ = std::move(other.deque_);
		}
		DequeMove& operator=(DequeMove&& other) noexcept
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			deque_ = std::move(other.deque_);
			return *this;
		}

		selfDqu take_all()
		{
			std::unique_lock lock(mutex_);
			return std::move(deque_);
		}
		void move_all(selfDqu&& other)
		{
			std::unique_lock lock(mutex_);
			deque_ = std::move(other);
		}

		/**
		 * @brief take one element by move
		 * @brief 以移动的方式取走某个元素
		 */
		T take(size_t index)
		{
			std::unique_lock lock(mutex_);
			auto tmp = std::move(deque_[index]);
			deque_.erase(deque_.begin() + index);
			return tmp;
		}
		/**
		 * @brief take first element by move
		 * @brief 以移动的方式取走首元素
		 */
		T take_front()
		{
			std::unique_lock lock(mutex_);
			auto tmp = std::move(deque_.front());
			deque_.erase(deque_.begin());
			return tmp;
		}
		/**
		 * @brief take back element by move
		 * @brief 以移动的方式取走尾元素
		 */
		T take_back()
		{
			std::unique_lock lock(mutex_);
			auto tmp = std::move(deque_.back());
			deque_.erase(deque_.end());
			return tmp;
		}

		bool empty()
		{
			std::shared_lock lock(mutex_);
			return deque_.empty();
		}
		size_t size()
		{
			std::shared_lock lock(mutex_);
			return deque_.size();
		}
		size_t max_size()
		{
			std::shared_lock lock(mutex_);
			return deque_.max_size();
		}
		void shrink_to_fit()
		{
			std::unique_lock lock(mutex_);
			return deque_.shrink_to_fit();
		}
		void clear()
		{
			std::unique_lock lock(mutex_);
			return deque_.clear();
		}
		void insert(size_t pos, T&& value)
		{
			std::unique_lock lock(mutex_);
			return deque_.insert(deque_.begin() + pos, std::move(value));
		}
		void emplace(size_t pos, T&& value)
		{
			std::unique_lock lock(mutex_);
			return deque_.emplace(deque_.begin() + pos, std::move(value));
		}
		void erase(size_t pos)
		{
			std::unique_lock lock(mutex_);
			return deque_.erase(deque_.begin() + pos);
		}
		void push_back(T&& value)
		{
			std::unique_lock lock(mutex_);
			deque_.push_back(std::move(value));
		}
		void emplace_back(T&& value)
		{
			std::unique_lock lock(mutex_);
			deque_.emplace_back(std::move(value));
		}
		void pop_back()
		{
			std::unique_lock lock(mutex_);
			deque_.pop_back();
		}
		void push_front(T&& value)
		{
			std::unique_lock lock(mutex_);
			deque_.push_front(std::move(value));
		}
		void emplace_front(T&& value)
		{
			std::unique_lock lock(mutex_);
			deque_.emplace_front(std::move(value));
		}
		void pop_front()
		{
			std::unique_lock lock(mutex_);
			deque_.pop_front();
		}
		/**
		 * @brief do something with selected elements
		 * @brief 对选定的元素进行操作
		 * @param pos the position of the selected element
		 * @param pos 元素的位置
		 * @param func the function to do
		 * @param func 要做的函数
		 */
		void doing(size_t pos, doSingleFunc func)
		{
			std::unique_lock lock(mutex_);
			func(deque_.begin() + pos);
		}
		/**
		 * @brief do something with all container
		 * @brief 对整个容器进行操作
		 * @param func the function to do
		 * @param func 要做的函数
		 */
		void doing(doContainerFunc func)
		{
			std::unique_lock lock(mutex_);
			func(deque_);
		}
		/**
		 * @brief do something with every elements
		 * @brief 对每个元素进行操作
		 * @param func the function to do
		 * @param func 要做的函数
		 */
		void doing(doLoopFunc func)
		{
			std::unique_lock lock(mutex_);
			for (auto it = deque_.begin(); it != deque_.end(); ++it)
			{
				func(deque_, it);
			}
		}
	};
}