#include "async/async_base.h"

namespace NSROOT = dog_torch::async;

std::string NSROOT::status_to_string(Status status)
{
	switch (status)
	{
	case Status::Created: return "Created";
	case Status::Ready: return "Ready";
	case Status::Running: return "Running";
	case Status::Blocked: return "Blocked";
	case Status::Stopped: return "Stopped";
	}
	return "";
}

#ifdef SHARED
extern template class CPP_API NSROOT::Clock<std::chrono::nanoseconds>;
extern template class CPP_API NSROOT::Clock<std::chrono::microseconds>;
extern template class CPP_API NSROOT::Clock<std::chrono::milliseconds>;
extern template class CPP_API NSROOT::Clock<std::chrono::seconds>;
extern template class CPP_API NSROOT::Clock<std::chrono::minutes>;
extern template class CPP_API NSROOT::Clock<std::chrono::hours>;
extern template class CPP_API NSROOT::Clock<std::chrono::days>;
extern template class CPP_API NSROOT::Clock<std::chrono::weeks>;

extern template class CPP_API NSROOT::AutoClock<std::chrono::nanoseconds>;
extern template class CPP_API NSROOT::AutoClock<std::chrono::microseconds>;
extern template class CPP_API NSROOT::AutoClock<std::chrono::milliseconds>;
extern template class CPP_API NSROOT::AutoClock<std::chrono::seconds>;
extern template class CPP_API NSROOT::AutoClock<std::chrono::minutes>;
extern template class CPP_API NSROOT::AutoClock<std::chrono::hours>;
extern template class CPP_API NSROOT::AutoClock<std::chrono::days>;
extern template class CPP_API NSROOT::AutoClock<std::chrono::weeks>;
#endif
