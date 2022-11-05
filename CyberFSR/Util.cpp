#include "pch.h"
#include "Config.h"
#include "Util.h"
#include <algorithm>
//#include <ffx_fsr2_interface.h>


#include <chrono>
// nanosecond precision
#define GetHighPrecisionTimeNow() std::chrono::steady_clock::now()

#define NanoSecondsBetween(a,b) std::chrono::duration_cast<std::chrono::nanoseconds>(b - a).count()
#define MilliSecondsBetween(a,b) std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count()

#define NanoSecondsNow() std::chrono::duration_cast<std::chrono::nanoseconds>(GetHighPrecisionTimeNow().time_since_epoch()).count()
#define MilliSecondsNow() std::chrono::duration_cast<std::chrono::milliseconds>(GetHighPrecisionTimeNow().time_since_epoch()).count()


namespace fs = std::filesystem;

extern HMODULE dllModule;

namespace CyberFSR
{
	fs::path Util::DllPath()
	{
		static fs::path dll;
		if (dll.empty())
		{
			wchar_t dllPath[MAX_PATH];
			GetModuleFileNameW(dllModule, dllPath, MAX_PATH);
			dll = fs::path(dllPath);
		}
		return dll;
	}

	fs::path Util::ExePath()
	{
		static fs::path exe;
		if (exe.empty())
		{
			wchar_t exePath[MAX_PATH];
			GetModuleFileNameW(nullptr, exePath, MAX_PATH);
			exe = fs::path(exePath);
		}
		return exe;
	}

	double Util::MillisecondsNow()
	{
		constexpr double MsinSec = (double)1 / (double)1000;

		static LARGE_INTEGER s_frequency;
		static int s_use_qpc = QueryPerformanceFrequency(&s_frequency);
		double milliseconds = 0;

		switch(s_use_qpc)
		{
		case 0:
			LARGE_INTEGER now;
			QueryPerformanceCounter(&now);
			milliseconds = double(1000.0 * now.QuadPart) / s_frequency.QuadPart;
			break;
		case 1:
			milliseconds = double(GetTickCount64()); //32bit overflows after 49days... unlikely to hit but still
			break;
		case 2:
		default:
			milliseconds = MilliSecondsNow() * MsinSec; //really fast chrono, use mult to keep it fast
			break;
		}

		return milliseconds;
	}

	float Util::ConvertSharpness(float sharpness, std::optional<SharpnessRangeModifier> range)
	{
		float output;

		if (range.has_value() && range.value() == SharpnessRangeModifier::Extended)
		{
			// normalize sharpness value to [0, 1] range
			// originally in range [-0.99, 1]
			output = ((sharpness * 2.0f ) + 1.98f) * 0.25f;
			output = std::clamp(output, 0.0f, 1.0f);
		}
		else
		{
			output = sharpness;
		}
		return output * 0.99f;
	}

	SharpnessRangeModifier Util::SharpnessRangeModifierMap(const char* in)
	{
		static std::unordered_map<std::string, SharpnessRangeModifier> Translation = {
			{"Normal", SharpnessRangeModifier::Normal},
			{"Extended", SharpnessRangeModifier::Extended}
		};
		return Translation[std::string(in)];
	};

	ViewMethod Util::ViewMethodMap(const char* in)
	{
		static std::unordered_map<std::string, ViewMethod> Translation = {
			{"Config", ViewMethod::Config},
			{"Cyberpunk2077", ViewMethod::Cyberpunk2077},
			{"RDR2", ViewMethod::RDR2}
		};
		return Translation[std::string(in)];
	};

	UpscalingProfile Util::UpscalingProfileMap(const char* in)
	{
		static std::unordered_map<std::string, UpscalingProfile> Translation = {
			{"FSR2", UpscalingProfile::FSR2},
			{"DLSS2", UpscalingProfile::DLSS2},
			{"DynaRes", UpscalingProfile::DynaRes},
			{"Fixed", UpscalingProfile::FixedRes}
		};
		return Translation[std::string(in)];
	};

	Util::NvParameter Util::NvParameterToEnum(const char* name)
	{
		static std::unordered_map<std::string, NvParameter> NvParamTranslation = {
			{NVSDK_NGX_Parameter_SuperSampling_ScaleFactor, NvParameter::SuperSampling_ScaleFactor},
			{NVSDK_NGX_Parameter_SuperSampling_Available, NvParameter::SuperSampling_Available},
			{NVSDK_NGX_Parameter_SuperSampling_MinDriverVersionMajor, NvParameter::SuperSampling_MinDriverVersionMajor},
			{NVSDK_NGX_Parameter_SuperSampling_MinDriverVersionMinor, NvParameter::SuperSampling_MinDriverVersionMinor},
			{NVSDK_NGX_Parameter_SuperSampling_FeatureInitResult, NvParameter::SuperSampling_FeatureInitResult},
			{NVSDK_NGX_Parameter_SuperSampling_NeedsUpdatedDriver, NvParameter::SuperSampling_NeedsUpdatedDriver},
			{NVSDK_NGX_EParameter_SuperSampling_Available, NvParameter::SuperSampling_Available_E},

			{NVSDK_NGX_Parameter_Width, NvParameter::Width},
			{NVSDK_NGX_Parameter_Height, NvParameter::Height},
			{NVSDK_NGX_Parameter_PerfQualityValue, NvParameter::PerfQualityValue},
			{NVSDK_NGX_Parameter_RTXValue, NvParameter::RTXValue},
			{NVSDK_NGX_Parameter_FreeMemOnReleaseFeature, NvParameter::FreeMemOnReleaseFeature},

			{NVSDK_NGX_Parameter_OutWidth, NvParameter::OutWidth},
			{NVSDK_NGX_Parameter_OutHeight, NvParameter::OutHeight},

			{NVSDK_NGX_Parameter_DLSS_Render_Subrect_Dimensions_Width, NvParameter::DLSS_Render_Subrect_Dimensions_Width},
			{NVSDK_NGX_Parameter_DLSS_Render_Subrect_Dimensions_Height, NvParameter::DLSS_Render_Subrect_Dimensions_Height},
			{NVSDK_NGX_Parameter_DLSS_Get_Dynamic_Max_Render_Width, NvParameter::DLSS_Get_Dynamic_Max_Render_Width},
			{NVSDK_NGX_Parameter_DLSS_Get_Dynamic_Max_Render_Height, NvParameter::DLSS_Get_Dynamic_Max_Render_Height},
			{NVSDK_NGX_Parameter_DLSS_Get_Dynamic_Min_Render_Width, NvParameter::DLSS_Get_Dynamic_Min_Render_Width},
			{NVSDK_NGX_Parameter_DLSS_Get_Dynamic_Min_Render_Height, NvParameter::DLSS_Get_Dynamic_Min_Render_Height},
			{NVSDK_NGX_Parameter_Sharpness, NvParameter::Sharpness},

			{NVSDK_NGX_Parameter_DLSSOptimalSettingsCallback, NvParameter::DLSSOptimalSettingsCallback},
			{NVSDK_NGX_Parameter_DLSSGetStatsCallback, NvParameter::DLSSGetStatsCallback},

			{NVSDK_NGX_Parameter_CreationNodeMask, NvParameter::CreationNodeMask},
			{NVSDK_NGX_Parameter_VisibilityNodeMask, NvParameter::VisibilityNodeMask},
			{NVSDK_NGX_Parameter_DLSS_Feature_Create_Flags, NvParameter::DLSS_Feature_Create_Flags},
			{NVSDK_NGX_Parameter_DLSS_Enable_Output_Subrects, NvParameter::DLSS_Enable_Output_Subrects},

			{NVSDK_NGX_Parameter_Color, NvParameter::Color},
			{NVSDK_NGX_Parameter_MotionVectors, NvParameter::MotionVectors},
			{NVSDK_NGX_Parameter_Depth, NvParameter::Depth},
			{NVSDK_NGX_Parameter_Output, NvParameter::Output},
			{NVSDK_NGX_Parameter_TransparencyMask, NvParameter::TransparencyMask},
			{NVSDK_NGX_Parameter_ExposureTexture, NvParameter::ExposureTexture},
			{NVSDK_NGX_Parameter_DLSS_Input_Bias_Current_Color_Mask, NvParameter::DLSS_Input_Bias_Current_Color_Mask},

			{NVSDK_NGX_Parameter_DLSS_Pre_Exposure, NvParameter::Pre_Exposure},
			{NVSDK_NGX_Parameter_DLSS_Exposure_Scale, NvParameter::Exposure_Scale},

			{NVSDK_NGX_Parameter_Reset, NvParameter::Reset},
			{NVSDK_NGX_Parameter_MV_Scale_X, NvParameter::MV_Scale_X},
			{NVSDK_NGX_Parameter_MV_Scale_Y, NvParameter::MV_Scale_Y},
			{NVSDK_NGX_Parameter_Jitter_Offset_X, NvParameter::Jitter_Offset_X},
			{NVSDK_NGX_Parameter_Jitter_Offset_Y, NvParameter::Jitter_Offset_Y},

			{NVSDK_NGX_Parameter_SizeInBytes, NvParameter::SizeInBytes},
			{NVSDK_NGX_Parameter_OptLevel, NvParameter::OptLevel},
			{NVSDK_NGX_EParameter_OptLevel, NvParameter::OptLevel_E},
			{NVSDK_NGX_Parameter_IsDevSnippetBranch, NvParameter::IsDevSnippetBranch},
			{NVSDK_NGX_EParameter_IsDevSnippetBranch, NvParameter::IsDevSnippetBranch_E},

			{NVSDK_NGX_Parameter_FrameTimeDeltaInMsec, NvParameter::FrameTimeDeltaInMsec},
		};

		return NvParamTranslation[std::string(name)];
	}
}