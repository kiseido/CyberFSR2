#include "pch.h"
#include "Config.h"
#include "Util.h"
#include "NvParameter.h"
#include "CyberFsr.h"

void NvParameter::Set(const char* InName, unsigned long long InValue)
{
	CyberLogArgs(InName, InValue);
	auto value = (unsigned long long*) & InValue;
	Set_Internal(InName, *value, NvULL);
}

void NvParameter::Set(const char* InName, float InValue)
{
	CyberLogArgs(InName, InValue);
	auto value = (unsigned long long*) & InValue;
	Set_Internal(InName, *value, NvFloat);
}

void NvParameter::Set(const char* InName, double InValue)
{
	CyberLogArgs(InName, InValue);
	auto value = (unsigned long long*) & InValue;
	Set_Internal(InName, *value, NvDouble);
}

void NvParameter::Set(const char* InName, unsigned int InValue)
{
	CyberLogArgs(InName, InValue);
	auto value = (unsigned long long*) & InValue;
	Set_Internal(InName, *value, NvUInt);
}

void NvParameter::Set(const char* InName, int InValue)
{
	CyberLogArgs(InName, InValue);
	auto value = (unsigned long long*) & InValue;
	Set_Internal(InName, *value, NvInt);
}

void NvParameter::Set(const char* InName, ID3D11Resource* InValue)
{
	CyberLOG(InName, InValue);
	auto value = (unsigned long long*) & InValue;
	Set_Internal(InName, *value, NvD3D11Resource);
}

void NvParameter::Set(const char* InName, ID3D12Resource* InValue)
{
	CyberLogArgs(InName, InValue);
	auto value = (unsigned long long*) & InValue;
	Set_Internal(InName, *value, NvD3D12Resource);
}

void NvParameter::Set(const char* InName, void* InValue)
{
	CyberLogArgs(InName, InValue);
	auto value = (unsigned long long*) & InValue;
	Set_Internal(InName, *value, NvVoidPtr);
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, unsigned long long* OutValue) const
{
	const auto result = Get_Internal(InName, (unsigned long long*)OutValue, NvULL);
	CyberLogArgs(InName, OutValue, *OutValue);
	return result;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, float* OutValue) const
{
	const auto result = Get_Internal(InName, (unsigned long long*)OutValue, NvFloat);
	CyberLogArgs(InName, OutValue, *OutValue);
	return result;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, double* OutValue) const
{
	const auto result = Get_Internal(InName, (unsigned long long*)OutValue, NvDouble);
	CyberLogArgs(InName, OutValue, *OutValue);
	return result;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, unsigned int* OutValue) const
{
	const auto result = Get_Internal(InName, (unsigned long long*)OutValue, NvUInt);
	CyberLogArgs(InName, OutValue, *OutValue);
	return result;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, int* OutValue) const
{
	const auto result = Get_Internal(InName, (unsigned long long*)OutValue, NvInt);
	CyberLogArgs(InName, OutValue, *OutValue);
	return result;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, ID3D11Resource** OutValue) const
{
	const auto result = Get_Internal(InName, (unsigned long long*)OutValue, NvD3D11Resource);
	CyberLogArgs(InName, OutValue, *OutValue);
	return result;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, ID3D12Resource** OutValue) const
{
	const auto result = Get_Internal(InName, (unsigned long long*)OutValue, NvD3D12Resource);
	CyberLogArgs(InName, OutValue, *OutValue);
	return result;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, void** OutValue) const
{
	const auto result = Get_Internal(InName, (unsigned long long*)OutValue, NvVoidPtr);
	CyberLogArgs(InName, OutValue, *OutValue);
	return result;
}

void NvParameter::Reset()
{
	CyberLogArgs();
}

inline void NvParameter::Set_Internal(const char* InName, unsigned long long InValue, NvParameterType ParameterType)
{
	//CyberLogArgs(InName, InValue, ParameterType);

	auto inValueFloat = (float*)&InValue;
	auto inValueInt = (int*)&InValue;
	auto inValueDouble = (double*)&InValue;
	auto inValueUInt = (unsigned int*)&InValue;
	//Includes DirectX Resources
	auto inValuePtr = (void*)InValue;

	switch (Util::NvParameterToEnum(InName))
	{
	case Util::NvParameter::MV_Scale_X:
		MVScaleX = *inValueFloat;
		break;
	case Util::NvParameter::MV_Scale_Y:
		MVScaleY = *inValueFloat;
		break;
	case Util::NvParameter::Jitter_Offset_X:
		JitterOffsetX = *inValueFloat;
		break;
	case Util::NvParameter::Jitter_Offset_Y:
		JitterOffsetY = *inValueFloat;
		break;
	case Util::NvParameter::Sharpness:
		Sharpness = *inValueFloat;
		break;
	case Util::NvParameter::Width:
		windowSize.Width = *inValueInt;
		break;
	case Util::NvParameter::Height:
		windowSize.Height = *inValueInt;
		break;
	case Util::NvParameter::DLSS_Render_Subrect_Dimensions_Width:
		renderSize.Width = *inValueInt;
		break;
	case Util::NvParameter::DLSS_Render_Subrect_Dimensions_Height:
		renderSize.Height = *inValueInt;
		break;
	case Util::NvParameter::PerfQualityValue:
		PerfQualityValue = static_cast<NVSDK_NGX_PerfQuality_Value>(*inValueInt);
		break;
	case Util::NvParameter::RTXValue:
		RTXValue = *inValueInt;
		break;
	case Util::NvParameter::FreeMemOnReleaseFeature:
		FreeMemOnReleaseFeature = *inValueInt;
		break;
	case Util::NvParameter::CreationNodeMask:
		CreationNodeMask = *inValueInt;
		break;
	case Util::NvParameter::VisibilityNodeMask:
		VisibilityNodeMask = *inValueInt;
		break;
	case Util::NvParameter::Reset:
		ResetRender = *inValueInt;
		break;
	case Util::NvParameter::OutWidth:
		renderSize.Width = *inValueInt;
		break;
	case Util::NvParameter::OutHeight:
		renderSize.Height = *inValueInt;
		break;
	case Util::NvParameter::DLSS_Feature_Create_Flags:
		Hdr = *inValueInt & NVSDK_NGX_DLSS_Feature_Flags_IsHDR;
		EnableSharpening = *inValueInt & NVSDK_NGX_DLSS_Feature_Flags_DoSharpening;
		DepthInverted = *inValueInt & NVSDK_NGX_DLSS_Feature_Flags_DepthInverted;
		JitterMotion = *inValueInt & NVSDK_NGX_DLSS_Feature_Flags_MVJittered;
		LowRes = *inValueInt & NVSDK_NGX_DLSS_Feature_Flags_MVLowRes;
		AutoExposure = *inValueInt & NVSDK_NGX_DLSS_Feature_Flags_AutoExposure;
		break;
	case Util::NvParameter::DLSS_Input_Bias_Current_Color_Mask:
		InputBiasCurrentColorMask = inValuePtr;
		if (InputBiasCurrentColorMask && ParameterType == NvParameterType::NvD3D12Resource)
			((ID3D12Resource*)InputBiasCurrentColorMask)->SetName(L"Color");
		break;
	case Util::NvParameter::Color:
		Color = inValuePtr;
		if (Color && ParameterType == NvParameterType::NvD3D12Resource)
			((ID3D12Resource*)Color)->SetName(L"Color");
		break;
	case Util::NvParameter::Depth:
		Depth = inValuePtr;
		if (Depth && ParameterType == NvParameterType::NvD3D12Resource)
			((ID3D12Resource*)Depth)->SetName(L"Depth");
		break;
	case Util::NvParameter::MotionVectors:
		MotionVectors = inValuePtr;
		if (MotionVectors && ParameterType == NvParameterType::NvD3D12Resource)
			((ID3D12Resource*)MotionVectors)->SetName(L"MotionVectors");
		break;
	case Util::NvParameter::Output:
		Output = inValuePtr;
		if (Output && ParameterType == NvParameterType::NvD3D12Resource)
			((ID3D12Resource*)Output)->SetName(L"Output");
		break;
	case Util::NvParameter::TransparencyMask:
		TransparencyMask = inValuePtr;
		if (TransparencyMask && ParameterType == NvParameterType::NvD3D12Resource)
			((ID3D12Resource*)TransparencyMask)->SetName(L"TransparencyMask");
		break;
	case Util::NvParameter::ExposureTexture:
		ExposureTexture = inValuePtr;
		if (ExposureTexture && ParameterType == NvParameterType::NvD3D12Resource)
			((ID3D12Resource*)ExposureTexture)->SetName(L"ExposureTexture");
		break;
	}
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetOptimalSettingsCallback(NVSDK_NGX_Parameter* InParams);
NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetStatsCallback(NVSDK_NGX_Parameter* InParams);

inline NVSDK_NGX_Result NvParameter::Get_Internal(const char* InName, unsigned long long* OutValue, NvParameterType ParameterType) const
{
	//CyberLogArgs(InName, OutValue, ParameterType);

	auto outValueFloat = (float*)OutValue;
	auto outValueInt = (int*)OutValue;
	auto outValueDouble = (double*)OutValue;
	auto outValueUInt = (unsigned int*)OutValue;
	auto outValueULL = (unsigned long long*)OutValue;
	//Includes DirectX Resources
	auto outValuePtr = (void**)OutValue;

	switch (Util::NvParameterToEnum(InName))
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
		*outValueInt = renderSize.Width;
		break;
	case Util::NvParameter::DLSS_Render_Subrect_Dimensions_Height:
		*outValueInt = renderSize.Height;
		break;
	case Util::NvParameter::OutWidth:
		*outValueInt = renderSize.Width;
		break;
	case Util::NvParameter::OutHeight:
		*outValueInt = renderSize.Height;
		break;
	case Util::NvParameter::DLSS_Get_Dynamic_Max_Render_Width:
		*outValueInt = renderSizeMax.Width;
		break;
	case Util::NvParameter::DLSS_Get_Dynamic_Max_Render_Height:
		*outValueInt = renderSizeMax.Height;
		break;
	case Util::NvParameter::DLSS_Get_Dynamic_Min_Render_Width:
		*outValueInt = renderSizeMin.Width;
		break;
	case Util::NvParameter::DLSS_Get_Dynamic_Min_Render_Height:
		*outValueInt = renderSizeMin.Height;
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
	case Util::NvParameter::RTXValue:
		*outValueInt = RTXValue;
		break;
	default:
		return NVSDK_NGX_Result_Fail;
	}

	return NVSDK_NGX_Result_Success;
}

// EvaluateRenderScale helper
inline FfxFsr2QualityMode DLSS2FSR2QualityTable(const NVSDK_NGX_PerfQuality_Value input)
{
	//CyberLogArgs(input);
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
		output = (FfxFsr2QualityMode)5; //Set out-of-range value for non-existing fsr ultra quality mode
		break;
	}

	return output;
}

// EvaluateRenderScale helper
inline std::optional<float> GetQualityOverrideRatio(const NVSDK_NGX_PerfQuality_Value input, const std::shared_ptr<const Config> config)
{
	//CyberLogArgs(input);
	std::optional<float> output;

	if (!(config->QualityRatioOverrideEnabled.has_value() && config->QualityRatioOverrideEnabled.value()))
		return output; // override not enabled

	switch (input)
	{
	case NVSDK_NGX_PerfQuality_Value_UltraPerformance:
		output = config->QualityRatio_UltraPerformance;
		break;
	case NVSDK_NGX_PerfQuality_Value_MaxPerf:
		output = config->QualityRatio_Performance;
		break;
	case NVSDK_NGX_PerfQuality_Value_Balanced:
		output = config->QualityRatio_Balanced;
		break;
	case NVSDK_NGX_PerfQuality_Value_MaxQuality:
		output = config->QualityRatio_Quality;
		break;
	case NVSDK_NGX_PerfQuality_Value_UltraQuality:
		output = config->QualityRatio_UltraQuality;
		break;
	default:
		// no correlated value, add some logging?
		break;
	}
	return output;
}

inline void ScaleDimensionsToRatios(NvParameter* parameter, float xRatio, float yRatio) {
	parameter->renderSize.Width = static_cast<unsigned int>(parameter->windowSize.Width / xRatio);
	parameter->renderSize.Height = static_cast<unsigned int>(parameter->windowSize.Height / yRatio);
}

inline void ScaleDimensionsToRatio(NvParameter* parameter, float ratio) {
	ScaleDimensionsToRatios(parameter, ratio, ratio);
}


void NvParameter::EvaluateRenderScale()
{

	//CyberLogArgs();
	const std::shared_ptr<Config> config = CyberFsrContext::instance()->MyConfig;

	if (screenSize.Height == 0 || screenSize.Width == 0) {
		screenSize.Width = GetSystemMetrics(SM_CXSCREEN);
		screenSize.Height = GetSystemMetrics(SM_CYSCREEN);
	}

	if (windowSize.Height == 0 || windowSize.Width == 0) {
		windowSize.Width = screenSize.Width;
		windowSize.Height = screenSize.Height;
	}

	renderSizeMin = {16,9};
	renderSizeMax = windowSize;

	//Static Upscale Ratio Override
	if (config->UpscaleRatioOverrideEnabled.value_or(false) && config->UpscaleRatioOverrideValue.has_value()) {
		ScaleDimensionsToRatio(this, *config->UpscaleRatioOverrideValue);
		return;
	}

	const std::optional<float> QualityRatio = GetQualityOverrideRatio(PerfQualityValue, config);

	//RTXValue = 1;

	if (QualityRatio.has_value()) {
		ScaleDimensionsToRatio(this, *QualityRatio);
		return;
	}

	const FfxFsr2QualityMode fsrQualityMode = DLSS2FSR2QualityTable(PerfQualityValue);

	if (fsrQualityMode < 5) {
		ffxFsr2GetRenderResolutionFromQualityMode(&renderSize.Width, &renderSize.Height, windowSize.Width, windowSize.Height, fsrQualityMode);
	}
	else {
		//Ultra Quality Mode
		renderSize.Width = windowSize.Width;
		renderSize.Height = windowSize.Height;
	}
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetOptimalSettingsCallback(NVSDK_NGX_Parameter* InParams)
{
	CyberLogArgs(InParams);
	auto params = static_cast<NvParameter*>(InParams);
	params->EvaluateRenderScale();
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetStatsCallback(NVSDK_NGX_Parameter* InParams)
{
	CyberLogArgs(InParams);
	//Somehow check for allocated memory
	//Then set values: SizeInBytes, OptLevel, IsDevSnippetBranch
	return NVSDK_NGX_Result_Success;
}