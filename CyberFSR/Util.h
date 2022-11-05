#pragma once
#include "Config.h"

namespace CyberFSR
{
	using ULongLong = unsigned long long;
	using ULongLongPtr = ULongLong*;

	namespace Util
	{
		std::filesystem::path ExePath();

		std::filesystem::path DllPath();

		double MillisecondsNow();

		float ConvertSharpness(float sharpness, std::optional<SharpnessRangeModifier> range);

		enum class NvParameter
		{
			Invalid,

			//SuperSampling
			SuperSampling_ScaleFactor,
			SuperSampling_Available,
			SuperSampling_Available_E,
			SuperSampling_MinDriverVersionMajor,
			SuperSampling_MinDriverVersionMinor,
			SuperSampling_FeatureInitResult,
			SuperSampling_NeedsUpdatedDriver,
			//User settings stuff
			Width,
			Height,
			PerfQualityValue,
			RTXValue,
			FreeMemOnReleaseFeature,
			//Resolution stuff
			OutWidth,
			OutHeight,

			DLSS_Render_Subrect_Dimensions_Width,
			DLSS_Render_Subrect_Dimensions_Height,
			DLSS_Get_Dynamic_Max_Render_Width,
			DLSS_Get_Dynamic_Max_Render_Height,
			DLSS_Get_Dynamic_Min_Render_Width,
			DLSS_Get_Dynamic_Min_Render_Height,
			Sharpness,
			//Callbacks
			DLSSGetStatsCallback,
			DLSSOptimalSettingsCallback,

			//Render stuff
			CreationNodeMask,
			VisibilityNodeMask,
			DLSS_Feature_Create_Flags,
			DLSS_Enable_Output_Subrects,

			//D3D12 Buffers
			Color,
			MotionVectors,
			Depth,
			Output,
			TransparencyMask,
			ExposureTexture,
			DLSS_Input_Bias_Current_Color_Mask,
			Pre_Exposure,
			Exposure_Scale,

			Reset,
			MV_Scale_X,
			MV_Scale_Y,
			Jitter_Offset_X,
			Jitter_Offset_Y,

			//Dev Stuff
			SizeInBytes,
			OptLevel,
			OptLevel_E,
			IsDevSnippetBranch,
			IsDevSnippetBranch_E,

			FrameTimeDeltaInMsec
		};

		NvParameter NvParameterToEnum(const char* name);
		UpscalingProfile UpscalingProfileMap(const char* name);
		ViewMethod ViewMethodMap(const char* name);
		SharpnessRangeModifier SharpnessRangeModifierMap(const char* name);
	}

	inline void ThrowIfFailed(HRESULT hr)
	{
		if (FAILED(hr))
		{
			// Set a breakpoint on this line to catch DirectX API errors
			throw std::exception();
		}
	}
	enum Error_Resilient_Boolean {
		ER_TRUE = ~0,
		ER_FALSE = 0,
		Unknown = ER_TRUE << (sizeof(int) * 8) / 2,
	};

	inline Error_Resilient_Boolean Sanitize_Bool(const Error_Resilient_Boolean& InValue) {
		Error_Resilient_Boolean output = Unknown;

		int scale = 0;

		for (int i = 0; i < sizeof(Error_Resilient_Boolean) * 8; i++) {
			bool bit = (InValue >> i) & 1;
			scale += bit ? 1 : -1;
		}
		if (scale < 0)
			output = ER_FALSE;
		else if (scale > 0)
			output = ER_TRUE;

		return output;
	};

}

inline FfxFsr2InitializationFlagBits operator&(const FfxFsr2InitializationFlagBits& a, const bool& b) {
	return b ? a : (FfxFsr2InitializationFlagBits)0;
}

inline FfxFsr2InitializationFlagBits operator&(const bool& b, const FfxFsr2InitializationFlagBits& a) {
	return b ? a : (FfxFsr2InitializationFlagBits)0;
}