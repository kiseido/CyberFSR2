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

Util::Hyper_NGX_Parameter Util::NvParameterToEnum(const char* name)
{
	//CyberLOG();
	static ankerl::unordered_dense::map<std::string, Hyper_NGX_Parameter> NvParamTranslation = {
		{"SuperSampling.ScaleFactor", Hyper_NGX_Parameter::SuperSampling_ScaleFactor},
		{"SuperSampling.Available", Hyper_NGX_Parameter::SuperSampling_Available},
		{"SuperSampling.MinDriverVersionMajor", Hyper_NGX_Parameter::SuperSampling_MinDriverVersionMajor},
		{"SuperSampling.MinDriverVersionMinor", Hyper_NGX_Parameter::SuperSampling_MinDriverVersionMinor},
		{"SuperSampling.FeatureInitResult", Hyper_NGX_Parameter::SuperSampling_FeatureInitResult},
		{"SuperSampling.NeedsUpdatedDriver", Hyper_NGX_Parameter::SuperSampling_NeedsUpdatedDriver},
		{"#\x01", Hyper_NGX_Parameter::SuperSampling_Available},

		{"Width", Hyper_NGX_Parameter::Width},
		{"Height", Hyper_NGX_Parameter::Height},
		{"PerfQualityValue", Hyper_NGX_Parameter::PerfQualityValue},
		{"RTXValue", Hyper_NGX_Parameter::RTXValue},
		{"NVSDK_NGX_Parameter_FreeMemOnReleaseFeature", Hyper_NGX_Parameter::FreeMemOnReleaseFeature},

		{"OutWidth", Hyper_NGX_Parameter::OutWidth},
		{"OutHeight", Hyper_NGX_Parameter::OutHeight},

		{"DLSS.Render.Subrect.Dimensions.Width", Hyper_NGX_Parameter::DLSS_Render_Subrect_Dimensions_Width},
		{"DLSS.Render.Subrect.Dimensions.Height", Hyper_NGX_Parameter::DLSS_Render_Subrect_Dimensions_Height},
		{"DLSS.Get.Dynamic.Max.Render.Width", Hyper_NGX_Parameter::DLSS_Get_Dynamic_Max_Render_Width},
		{"DLSS.Get.Dynamic.Max.Render.Height", Hyper_NGX_Parameter::DLSS_Get_Dynamic_Max_Render_Height},
		{"DLSS.Get.Dynamic.Min.Render.Width", Hyper_NGX_Parameter::DLSS_Get_Dynamic_Min_Render_Width},
		{"DLSS.Get.Dynamic.Min.Render.Height", Hyper_NGX_Parameter::DLSS_Get_Dynamic_Min_Render_Height},
		{"Sharpness", Hyper_NGX_Parameter::Sharpness},

		{"DLSSOptimalSettingsCallback", Hyper_NGX_Parameter::DLSSOptimalSettingsCallback},
		{"DLSSGetStatsCallback", Hyper_NGX_Parameter::DLSSGetStatsCallback},

		{"CreationNodeMask", Hyper_NGX_Parameter::CreationNodeMask},
		{"VisibilityNodeMask", Hyper_NGX_Parameter::VisibilityNodeMask},
		{"DLSS.Feature.Create.Flags", Hyper_NGX_Parameter::DLSS_Feature_Create_Flags},
		{"DLSS.Enable.Output.Subrects", Hyper_NGX_Parameter::DLSS_Enable_Output_Subrects},

		{"Color", Hyper_NGX_Parameter::Color},
		{"MotionVectors", Hyper_NGX_Parameter::MotionVectors},
		{"Depth", Hyper_NGX_Parameter::Depth},
		{"Output", Hyper_NGX_Parameter::Output},
		{"TransparencyMask", Hyper_NGX_Parameter::TransparencyMask},
		{"ExposureTexture", Hyper_NGX_Parameter::ExposureTexture},
		{"DLSS.Input.Bias.Current.Color.Mask", Hyper_NGX_Parameter::DLSS_Input_Bias_Current_Color_Mask},

		{"DLSS.Pre.Exposure", Hyper_NGX_Parameter::Pre_Exposure},
		{"DLSS.Exposure.Scale", Hyper_NGX_Parameter::Exposure_Scale},

		{"Reset", Hyper_NGX_Parameter::Reset},
		{"MV.Scale.X", Hyper_NGX_Parameter::MV_Scale_X},
		{"MV.Scale.Y", Hyper_NGX_Parameter::MV_Scale_Y},
		{"Jitter.Offset.X", Hyper_NGX_Parameter::Jitter_Offset_X},
		{"Jitter.Offset.Y", Hyper_NGX_Parameter::Jitter_Offset_Y},

		{"SizeInBytes", Hyper_NGX_Parameter::SizeInBytes},
		{"Snippet.OptLevel", Hyper_NGX_Parameter::OptLevel},
		{"#\x44", Hyper_NGX_Parameter::OptLevel},
		{"Snippet.IsDevBranch", Hyper_NGX_Parameter::IsDevSnippetBranch},
		{"#\x45", Hyper_NGX_Parameter::IsDevSnippetBranch}
	};

	return NvParamTranslation[std::string(name)];
}
