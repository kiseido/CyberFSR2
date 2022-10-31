#include "pch.h"
#include "Config.h"
#include "Util.h"
#include "NvParameter.h"
#include "CyberFsr.h"

using ULongLong = unsigned long long;
using ULongLongPtr = ULongLong*;

void NvParameter::Set(const char* InName, unsigned long long InValue)
{
	constexpr auto nvType = NvULL;
	Set_Internal(InName, (ULongLong) InValue, nvType);
}

void NvParameter::Set(const char* InName, float InValue)
{
	constexpr auto nvType = NvFloat;
	Set_Internal(InName, (ULongLong)InValue, nvType);
}

void NvParameter::Set(const char* InName, double InValue)
{
	constexpr auto nvType = NvDouble;
	Set_Internal(InName, (ULongLong)InValue, nvType);
}

void NvParameter::Set(const char* InName, unsigned int InValue)
{
	constexpr auto nvType = NvUInt;
	Set_Internal(InName, (ULongLong)InValue, nvType);
}

void NvParameter::Set(const char* InName, int InValue)
{
	constexpr auto nvType = NvInt;
	Set_Internal(InName, (ULongLong)InValue, nvType);
}

void NvParameter::Set(const char* InName, ID3D11Resource* InValue)
{
	constexpr auto nvType = NvD3D11Resource;
	Set_Internal(InName, (ULongLong)InValue, nvType);
}

void NvParameter::Set(const char* InName, ID3D12Resource* InValue)
{
	constexpr auto nvType = NvD3D12Resource;
	Set_Internal(InName, (ULongLong)InValue, nvType);
}

void NvParameter::Set(const char* InName, void* InValue)
{
	constexpr auto nvType = NvVoidPtr;
	Set_Internal(InName, (ULongLong)InValue, nvType);
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, unsigned long long* OutValue) const
{
	constexpr auto nvType = NvULL;
	return Get_Internal(InName, (ULongLongPtr)OutValue, nvType);
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, float* OutValue) const
{
	constexpr auto nvType = NvFloat;
	return Get_Internal(InName, (ULongLongPtr)OutValue, nvType);
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, double* OutValue) const
{
	constexpr auto nvType = NvDouble;
	return Get_Internal(InName, (ULongLongPtr)OutValue, nvType);
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, unsigned int* OutValue) const
{
	constexpr auto nvType = NvUInt;
	return Get_Internal(InName, (ULongLongPtr)OutValue, nvType);
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, int* OutValue) const
{
	constexpr auto nvType = NvInt;
	return Get_Internal(InName, (ULongLongPtr)OutValue, nvType);
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, ID3D11Resource** OutValue) const
{
	constexpr auto nvType = NvD3D11Resource;
	return Get_Internal(InName, (ULongLongPtr)OutValue, nvType);
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, ID3D12Resource** OutValue) const
{
	constexpr auto nvType = NvD3D12Resource;
	return Get_Internal(InName, (ULongLongPtr)OutValue, nvType);
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, void** OutValue) const
{
	constexpr auto nvType = NvVoidPtr;
	return Get_Internal(InName, (ULongLongPtr)OutValue, nvType);
}

void NvParameter::Reset()
{
}

void NvParameter::Set_Internal(const char* InName, unsigned long long InValue, NvParameterType ParameterType)
{
	float const& inValueFloat = (float)InValue;
	int const& inValueInt = (int)InValue;
	double const& inValueDouble = (double)InValue;
	unsigned int const& inValueUInt = (unsigned int)InValue;
	//Includes DirectX Resources
	void* const& inValuePtr = (void*)InValue;

	const Util::NvParameter inParameter = Util::NvParameterToEnum(InName);

	switch (inParameter)
	{
	case Util::NvParameter::MV_Scale_X:
		MVScaleX = inValueFloat;
		break;
	case Util::NvParameter::MV_Scale_Y:
		MVScaleY = inValueFloat;
		break;
	case Util::NvParameter::Jitter_Offset_X:
		JitterOffsetX = inValueFloat;
		break;
	case Util::NvParameter::Jitter_Offset_Y:
		JitterOffsetY = inValueFloat;
		break;
	case Util::NvParameter::Sharpness:
		Sharpness = inValueFloat;
		break;
	case Util::NvParameter::Width:
		Width = inValueInt;
		break;
	case Util::NvParameter::Height:
		Height = inValueInt;
		break;
	case Util::NvParameter::DLSS_Render_Subrect_Dimensions_Width:
		Width = inValueInt;
		break;
	case Util::NvParameter::DLSS_Render_Subrect_Dimensions_Height:
		Height = inValueInt;
		break;
	case Util::NvParameter::PerfQualityValue:
		PerfQualityValue = static_cast<NVSDK_NGX_PerfQuality_Value>(inValueInt);
		break;
	case Util::NvParameter::RTXValue:
		RTXValue = inValueInt;
		break;
	case Util::NvParameter::FreeMemOnReleaseFeature:
		FreeMemOnReleaseFeature = inValueInt;
		break;
	case Util::NvParameter::CreationNodeMask:
		CreationNodeMask = inValueInt;
		break;
	case Util::NvParameter::VisibilityNodeMask:
		VisibilityNodeMask = inValueInt;
		break;
	case Util::NvParameter::Reset:
		ResetRender = inValueInt;
		break;
	case Util::NvParameter::OutWidth:
		OutWidth = inValueInt;
		break;
	case Util::NvParameter::OutHeight:
		OutHeight = inValueInt;
		break;
	case Util::NvParameter::DLSS_Feature_Create_Flags:
		Hdr =				inValueInt & NVSDK_NGX_DLSS_Feature_Flags_IsHDR;
		EnableSharpening =	inValueInt & NVSDK_NGX_DLSS_Feature_Flags_DoSharpening;
		DepthInverted =		inValueInt & NVSDK_NGX_DLSS_Feature_Flags_DepthInverted;
		JitterMotion =		inValueInt & NVSDK_NGX_DLSS_Feature_Flags_MVJittered;
		LowRes =			inValueInt & NVSDK_NGX_DLSS_Feature_Flags_MVLowRes;
		break;
		// Set_Internal helper
#define SetNVarWithName(setVar, name) if ((setVar = inValuePtr) && ParameterType == NvParameterType::NvD3D12Resource) ((ID3D12Resource*)setVar)->SetName(name)
	case Util::NvParameter::DLSS_Input_Bias_Current_Color_Mask:
		SetNVarWithName(InputBiasCurrentColorMask, L"Color");
		break;
	case Util::NvParameter::Color:
		SetNVarWithName(Color, L"Color");
		break;
	case Util::NvParameter::Depth:
		SetNVarWithName(Depth, L"Depth");
		break;
	case Util::NvParameter::MotionVectors:
		SetNVarWithName(MotionVectors, L"MotionVectors");
		break;
	case Util::NvParameter::Output:
		SetNVarWithName(Output, L"Output");
		break;
	case Util::NvParameter::TransparencyMask:
		SetNVarWithName(TransparencyMask, L"TransparencyMask");
		break;
	case Util::NvParameter::ExposureTexture:
		SetNVarWithName(ExposureTexture, L"ExposureTexture");
		break;
	}
#undef SetNVarWithName
}

	NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetOptimalSettingsCallback(NVSDK_NGX_Parameter* InParams);
	NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetStatsCallback(NVSDK_NGX_Parameter* InParams);

NVSDK_NGX_Result NvParameter::Get_Internal(const char* InName, unsigned long long* OutValue, NvParameterType ParameterType) const
{
	const Util::NvParameter inParameter = Util::NvParameterToEnum(InName);

	float* const& outValueFloat = (float*)OutValue;
	int* const& outValueInt = (int*)OutValue;
	double* const& outValueDouble = (double*)OutValue;
	unsigned int* const& outValueUInt = (unsigned int*)OutValue;
	unsigned long long* const& outValueULL = (unsigned long long*)OutValue;
	//Includes DirectX Resources
	void** const& outValuePtr = (void**)OutValue;

	switch (inParameter)
	{
	case Util::NvParameter::Sharpness:
		*outValueFloat = Sharpness;
		break;
	case Util::NvParameter::SuperSampling_Available:
		*outValueInt = true;
		break;
	case Util::NvParameter::SuperSampling_FeatureInitResult:
		*outValueInt = NVSDK_NGX_Result_Success;
		break;
	case Util::NvParameter::SuperSampling_NeedsUpdatedDriver:
		*outValueInt = 0;
		break;
	case Util::NvParameter::SuperSampling_MinDriverVersionMinor:
	case Util::NvParameter::SuperSampling_MinDriverVersionMajor:
		*outValueInt = 0;
		break;
	case Util::NvParameter::DLSS_Render_Subrect_Dimensions_Width:
		*outValueInt = Width;
		break;
	case Util::NvParameter::DLSS_Render_Subrect_Dimensions_Height:
		*outValueInt = Height;
		break;
	case Util::NvParameter::OutWidth:
		*outValueInt = OutWidth;
		break;
	case Util::NvParameter::OutHeight:
		*outValueInt = OutHeight;
		break;
	case Util::NvParameter::DLSS_Get_Dynamic_Max_Render_Width:
		*outValueInt = Width;
		break;
	case Util::NvParameter::DLSS_Get_Dynamic_Max_Render_Height:
		*outValueInt = Height;
		break;
	case Util::NvParameter::DLSS_Get_Dynamic_Min_Render_Width:
		*outValueInt = OutWidth;
		break;
	case Util::NvParameter::DLSS_Get_Dynamic_Min_Render_Height:
		*outValueInt = OutHeight;
		break;
	case Util::NvParameter::DLSSOptimalSettingsCallback:
		*outValuePtr = NVSDK_NGX_DLSS_GetOptimalSettingsCallback;
		break;
	case Util::NvParameter::DLSSGetStatsCallback:
		*outValuePtr = NVSDK_NGX_DLSS_GetStatsCallback;
		break;
	case Util::NvParameter::SizeInBytes:
		*outValueULL = 0x1337; //Dummy value
		break;
	case Util::NvParameter::OptLevel:
		*outValueInt = 0; //Dummy value
		break;
	case Util::NvParameter::IsDevSnippetBranch:
		*outValueInt = 0; //Dummy value
		break;
	default:
		return NVSDK_NGX_Result_Fail;
		break;
	}
	return NVSDK_NGX_Result_Success;
}

// EvaluateRenderScale helper
inline std::optional<FfxFsr2QualityMode> DLSS2FSR2QualityTable(const NVSDK_NGX_PerfQuality_Value& input)
{
	FfxFsr2QualityMode output;

	switch (input)
	{
	case NVSDK_NGX_PerfQuality_Value_UltraPerformance:
		output = FFX_FSR2_QUALITY_MODE_ULTRA_PERFORMANCE;
		break;
	case NVSDK_NGX_PerfQuality_Value_MaxPerf:
		output = FFX_FSR2_QUALITY_MODE_PERFORMANCE;
		break;
	case NVSDK_NGX_PerfQuality_Value_Balanced:
		output = FFX_FSR2_QUALITY_MODE_BALANCED;
		break;
	case NVSDK_NGX_PerfQuality_Value_MaxQuality:
		output = FFX_FSR2_QUALITY_MODE_QUALITY;
		break;
	case NVSDK_NGX_PerfQuality_Value_UltraQuality:
	default:
		// no correlated value, add some logging?
		return std::nullopt;
	}
	return output;
}

// EvaluateRenderScale helper
inline std::optional<float> GetQualityOverrideRatio(const NVSDK_NGX_PerfQuality_Value& input, const std::shared_ptr<Config>& config)
{
	constexpr float NO_VALUE = 0;

	float output = NO_VALUE;

	switch (input)
	{
	case NVSDK_NGX_PerfQuality_Value_UltraPerformance:
		output = config->QualityRatio_UltraPerformance.value_or(NO_VALUE);
		break;
	case NVSDK_NGX_PerfQuality_Value_MaxPerf:
		output = config->QualityRatio_Performance.value_or(NO_VALUE);
		break;
	case NVSDK_NGX_PerfQuality_Value_Balanced:
		output = config->QualityRatio_Balanced.value_or(NO_VALUE);
		break;
	case NVSDK_NGX_PerfQuality_Value_MaxQuality:
		output = config->QualityRatio_Quality.value_or(NO_VALUE);
		break;
	case NVSDK_NGX_PerfQuality_Value_UltraQuality:
		output = config->QualityRatio_UltraQuality.value_or(NO_VALUE);
		break;
	default:
		// no correlated value, add some logging?
		break;
	}
	if (output == NO_VALUE)
		return std::nullopt;

	return output;
}

void NvParameter::EvaluateRenderScale()
{
	// multiply is generally significantly faster than divide, so store ratio as a multiple
	constexpr double defaultRatioVertical = 1.0f / 2.0f;
	constexpr double defaultRatioHorizontal = 1.0f / 2.0f;

	std::shared_ptr<Config> config = CyberFsrContext::instance()->MyConfig;

	std::optional<float> QualityRatio = GetQualityOverrideRatio(PerfQualityValue, config);

	if (QualityRatio.has_value()) {
		// do a single division now to save on divison later
		const double resDivisionRatio = QualityRatio.value();
		const double resolutionRatio = 1.0 / resDivisionRatio;

		const double resolutionRatioVertical = resolutionRatio;
		const double resolutionRatioHorizontal = resolutionRatio;

		// Multiply is faster than divide, double is vastly more accurate than float
		OutHeight = (unsigned int)(Height * resolutionRatioVertical);
		OutWidth = (unsigned int)(Width * resolutionRatioHorizontal);
	}
	else 
	{
		const std::optional<FfxFsr2QualityMode>& fsrQualityMode = DLSS2FSR2QualityTable(PerfQualityValue);
		if (fsrQualityMode.has_value()) 
		{
			const auto err = ffxFsr2GetRenderResolutionFromQualityMode(&OutWidth, &OutHeight, Width, Height, fsrQualityMode.value());
#ifdef _DEBUG
			switch (err)
			{
			case FFX_OK:
				// all good!
				break;
			case FFX_ERROR_INVALID_POINTER:
				printf("EvaluateRenderScale error: FFX_ERROR_INVALID_POINTER");
				break;
			case FFX_ERROR_INVALID_ENUM:
				printf("EvaluateRenderScale error: FFX_ERROR_INVALID_ENUM");
				break;
			default:
				printf("EvaluateRenderScale error: default");
				// bad crap!
				break;
			}
#endif
		}
		else {
			// have to have some sort of default unless we want to crash?
			OutHeight = (unsigned int)(Height * defaultRatioVertical);
			OutWidth = (unsigned int)(Width * defaultRatioHorizontal);
		}
	}

	NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetOptimalSettingsCallback(NVSDK_NGX_Parameter* InParams)
	{
		auto* params = (NvParameter*)InParams;
		params->EvaluateRenderScale();
		return NVSDK_NGX_Result_Success;
	}

	NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetStatsCallback(NVSDK_NGX_Parameter* InParams)
	{
		//Somehow check for allocated memory
		//Then set values: SizeInBytes, OptLevel, IsDevSnippetBranch
		return NVSDK_NGX_Result_Success;
	}
}