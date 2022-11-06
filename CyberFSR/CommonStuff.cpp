#include "pch.h"
#include "CommonStuff.h"

#include <chrono>

namespace CyberFSR {
	inline auto Timer::GetHighPrecisionTimeNow()
	{
		return std::chrono::steady_clock::now();
	}

	inline auto Timer::NanoSecondsBetween(const auto& a, const auto& b)
	{
		return std::chrono::duration_cast<std::chrono::nanoseconds>(b - a).count();
	}

	inline auto Timer::MilliSecondsBetween(const auto& a, const auto& b)
	{
		return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count();
	}

	long long Timer::NanoSecondsNow()
	{
		return std::chrono::duration_cast<std::chrono::nanoseconds>(GetHighPrecisionTimeNow().time_since_epoch()).count();
	}

	long long Timer::MilliSecondsNow()
	{
		return std::chrono::duration_cast<std::chrono::milliseconds>(GetHighPrecisionTimeNow().time_since_epoch()).count();
	}

	void CyberFSR::BadThingHappened()
	{
		static int a = 0;
		a++;
	}
}