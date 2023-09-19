#include "pch.h"
#include "Config.h"
#include "Util.h"
#include "CFSR_Logging.h"

namespace fs = std::filesystem;

extern HMODULE dllModule;

fs::path Util::DllPath()
{
	CyberLOG();
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
	CyberLOG();
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
	CyberLOG();
	static LARGE_INTEGER s_frequency;
	static BOOL s_use_qpc = QueryPerformanceFrequency(&s_frequency);
	double milliseconds = 0;

	if (s_use_qpc)
	{
		LARGE_INTEGER now;
		QueryPerformanceCounter(&now);
		milliseconds = double(1000.0 * now.QuadPart) / s_frequency.QuadPart;
	}
	else
	{
		milliseconds = double(GetTickCount());
	}

	return milliseconds;
}

float Util::ConvertSharpness(float sharpness, std::optional<SharpnessRangeModifier> range)
{
	CyberLOG();

	if (!range.has_value())
		return sharpness;

	if (range == SharpnessRangeModifier::Extended)
	{
		// normalize sharpness value to [0, 1] range
		// originally in range [-0.99, 1]
		if (sharpness >= 1.0f)
		{
			return 1.0f;
		}
		else if (sharpness <= -1.0f)
		{
			return 0;
		}
		else
		{
			return (sharpness + 0.99f) / 2.0f;
		}
	}
	else
	{
		return sharpness;
	}
}

Util::Parameter Util::NvParameterToEnum(const char* name)
{
	//CyberLOG();
	static ankerl::unordered_dense::map<std::string, Parameter> NvParamTranslation = {
		{"SuperSampling.ScaleFactor", Parameter::SuperSampling_ScaleFactor},
		{"SuperSampling.Available", Parameter::SuperSampling_Available},
		{"SuperSampling.MinDriverVersionMajor", Parameter::SuperSampling_MinDriverVersionMajor},
		{"SuperSampling.MinDriverVersionMinor", Parameter::SuperSampling_MinDriverVersionMinor},
		{"SuperSampling.FeatureInitResult", Parameter::SuperSampling_FeatureInitResult},
		{"SuperSampling.NeedsUpdatedDriver", Parameter::SuperSampling_NeedsUpdatedDriver},
		{"#\x01", Parameter::SuperSampling_Available},

		{"Width", Parameter::Width},
		{"Height", Parameter::Height},
		{"PerfQualityValue", Parameter::PerfQualityValue},
		{"RTXValue", Parameter::RTXValue},
		{"NVSDK_NGX_Parameter_FreeMemOnReleaseFeature", Parameter::FreeMemOnReleaseFeature},

		{"OutWidth", Parameter::OutWidth},
		{"OutHeight", Parameter::OutHeight},

		{"DLSS.Render.Subrect.Dimensions.Width", Parameter::DLSS_Render_Subrect_Dimensions_Width},
		{"DLSS.Render.Subrect.Dimensions.Height", Parameter::DLSS_Render_Subrect_Dimensions_Height},
		{"DLSS.Get.Dynamic.Max.Render.Width", Parameter::DLSS_Get_Dynamic_Max_Render_Width},
		{"DLSS.Get.Dynamic.Max.Render.Height", Parameter::DLSS_Get_Dynamic_Max_Render_Height},
		{"DLSS.Get.Dynamic.Min.Render.Width", Parameter::DLSS_Get_Dynamic_Min_Render_Width},
		{"DLSS.Get.Dynamic.Min.Render.Height", Parameter::DLSS_Get_Dynamic_Min_Render_Height},
		{"Sharpness", Parameter::Sharpness},

		{"DLSSOptimalSettingsCallback", Parameter::DLSSOptimalSettingsCallback},
		{"DLSSGetStatsCallback", Parameter::DLSSGetStatsCallback},

		{"CreationNodeMask", Parameter::CreationNodeMask},
		{"VisibilityNodeMask", Parameter::VisibilityNodeMask},
		{"DLSS.Feature.Create.Flags", Parameter::DLSS_Feature_Create_Flags},
		{"DLSS.Enable.Output.Subrects", Parameter::DLSS_Enable_Output_Subrects},

		{"Color", Parameter::Color},
		{"MotionVectors", Parameter::MotionVectors},
		{"Depth", Parameter::Depth},
		{"Output", Parameter::Output},
		{"TransparencyMask", Parameter::TransparencyMask},
		{"ExposureTexture", Parameter::ExposureTexture},
		{"DLSS.Input.Bias.Current.Color.Mask", Parameter::DLSS_Input_Bias_Current_Color_Mask},

		{"DLSS.Pre.Exposure", Parameter::Pre_Exposure},
		{"DLSS.Exposure.Scale", Parameter::Exposure_Scale},

		{"Reset", Parameter::Reset},
		{"MV.Scale.X", Parameter::MV_Scale_X},
		{"MV.Scale.Y", Parameter::MV_Scale_Y},
		{"Jitter.Offset.X", Parameter::Jitter_Offset_X},
		{"Jitter.Offset.Y", Parameter::Jitter_Offset_Y},

		{"SizeInBytes", Parameter::SizeInBytes},
		{"Snippet.OptLevel", Parameter::OptLevel},
		{"#\x44", Parameter::OptLevel},
		{"Snippet.IsDevBranch", Parameter::IsDevSnippetBranch},
		{"#\x45", Parameter::IsDevSnippetBranch}
	};

	return NvParamTranslation[std::string(name)];
}
