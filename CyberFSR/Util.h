#pragma once
// #include "Config.h"
#include "CommonStuff.h"

namespace CyberFSR
{
	namespace Util
	{
		static int TimerType = 2;
		std::filesystem::path ExePath();

		std::filesystem::path DllPath();

		double MillisecondsNow();

		float ConvertSharpness(float sharpness, std::optional<SharpnessRangeModifier> range);
		float DynaRes(float TargetMillisecondsPerFrame, bool doTimeInternal, float& MillisecondsSinceLastFrame);

		NvParameter NvParameterToEnum(const char* name);
		UpscalingProfile UpscalingProfileMap(const char* name);
		ViewMethod ViewMethodMap(const char* name);
		SharpnessRangeModifier SharpnessRangeModifierMap(const char* name);
		void FFXErrorCheck(FfxErrorCode errorCode);
	}

	inline void ThrowIfFailed(HRESULT hr)
	{
		if (FAILED(hr))
		{
			// Set a breakpoint on this line to catch DirectX API errors
			throw std::exception();
		}
	}

	inline Error_Resilient_Boolean Sanitize_Bool(const Error_Resilient_Boolean& InValue) {
		int output = (int) Error_Resilient_Boolean::Unknown;

		const int& InValueInt = (int)InValue;

		int scale = 0;

		for (int i = 0; i < sizeof(Error_Resilient_Boolean) * 8; i++) {
			bool bit = (InValueInt >> i) & 1;
			scale += bit ? 1 : -1;
		}
		if (scale < 0)
			output = (int) Error_Resilient_Boolean::ER_FALSE;
		else if (scale > 0)
			output = (int) Error_Resilient_Boolean::ER_TRUE;

		return (Error_Resilient_Boolean) output;
	};


}

inline FfxFsr2InitializationFlagBits operator&(const FfxFsr2InitializationFlagBits& a, const bool& b) {
	return b ? a : (FfxFsr2InitializationFlagBits)0;
}

inline FfxFsr2InitializationFlagBits operator&(const bool& b, const FfxFsr2InitializationFlagBits& a) {
	return b ? a : (FfxFsr2InitializationFlagBits)0;
}