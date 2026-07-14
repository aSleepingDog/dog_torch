#include "async/thread/async_thread_base.h"

namespace NSROOT = dog_torch::async::thread;

NSROOT::PauseableChannel::PauseableChannel(bool need_clock) : clock_(need_clock ? std::make_unique<Clock<std::chrono::milliseconds>>() : nullptr)
{
    this->condition_variable_ = std::make_unique<std::condition_variable>();
}
NSROOT::PauseableChannel::PauseableChannel(PauseableChannel&& other) noexcept
{
    std::scoped_lock lock(mutex_, other.mutex_);
    this->clock_ = std::move(other.clock_);
    this->condition_variable_ = std::move(other.condition_variable_);
    this->status_ = other.status_.load();
    this->progress_ = other.progress_.load();
}
NSROOT::PauseableChannel& NSROOT::PauseableChannel::operator=(PauseableChannel&& other) noexcept
{
    std::scoped_lock lock(mutex_, other.mutex_);
    if (this == &other) return *this;
    this->clock_ = std::move(other.clock_);
    this->condition_variable_ = std::move(other.condition_variable_);
    this->status_ = other.status_.load();
    this->progress_ = other.progress_.load();
    return *this;
}
dog_torch::async::Status NSROOT::PauseableChannel::status() const
{
    return this->status_.load();
}

void NSROOT::PauseableChannel::start()
{
    if (this->status_.load() != Status::Ready) return;
    this->status_.store(Status::Running);
    if (this->clock_) this->clock_->start();
}
void NSROOT::PauseableChannel::pause()
{
    if (this->status_.load() != Status::Running) return;
    this->status_.store(Status::Blocked);
    if (this->clock_) this->clock_->pause();
}
bool NSROOT::PauseableChannel::check_status()
{
    std::unique_lock lock(this->mutex_);
    if (this->status_.load() == Status::Blocked)
    {
        this->condition_variable_->wait(lock, [this]()->bool
            {
                return this->status_.load() != Status::Blocked;
            }
        );
    }
    return this->status_ == Status::Stopped;
}
void NSROOT::PauseableChannel::resume()
{
    std::unique_lock lock(this->mutex_);
    if (this->status_.load() != Status::Blocked) return;
    this->status_.store(Status::Running);
    this->condition_variable_->notify_one();
    if (this->clock_) this->clock_->resume();
}
void NSROOT::PauseableChannel::stop()
{
    if (this->status_.load() != Status::Running && this->status_ != Status::Blocked) return;
    std::unique_lock lock(this->mutex_);
    this->status_.store(Status::Stopped);
    this->condition_variable_->notify_one();
    if (this->clock_) this->clock_->stop();
}
void NSROOT::PauseableChannel::reset()
{
    if (this->status_.load() != Status::Stopped)return;
    this->status_.store(Status::Ready);
    this->progress_.store(0.0);
    if (this->clock_) this->clock_->reset();
}
NSROOT::PauseableDetail NSROOT::PauseableChannel::to_detail()
{
    PauseableDetail r;
    r.status = this->status_.load();
    r.progress = this->progress_.load();
    if (this->clock_) r.time = this->clock_->elapsed();
    return r;
}
void NSROOT::PauseableChannel::set_progress(double progress)
{
    this->progress_.store(progress);
}
void NSROOT::PauseableChannel::add_progress(double progress)
{
    this->progress_.fetch_add(progress);
}
double NSROOT::PauseableChannel::get_progress()
{
    return this->progress_.load();
}

#undef NSROOT
