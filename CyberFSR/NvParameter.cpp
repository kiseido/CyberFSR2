#include "pch.h"
#include "Config.h"
#include "Util.h"
#include "NvParameter.h"
#include "CyberFsr.h"

#include <numeric>
#include <algorithm>

void NvParameter::Set(const char* InName, unsigned long long InValue)
{
	CyberLogArgs(this, InName, InValue);
	auto value = (unsigned long long*) & InValue;
	Set_Internal(InName, *value, NvULL);
}

void NvParameter::Set(const char* InName, float InValue)
{
	CyberLogArgs(this, InName, InValue);
	auto value = (unsigned long long*) & InValue;
	Set_Internal(InName, *value, NvFloat);
}

void NvParameter::Set(const char* InName, double InValue)
{
	CyberLogArgs(this, InName, InValue);
	auto value = (unsigned long long*) & InValue;
	Set_Internal(InName, *value, NvDouble);
}

void NvParameter::Set(const char* InName, unsigned int InValue)
{
	CyberLogArgs(this, InName, InValue);
	auto value = (unsigned long long*) & InValue;
	Set_Internal(InName, *value, NvUInt);
}

void NvParameter::Set(const char* InName, int InValue)
{
	CyberLogArgs(this, InName, InValue);
	auto value = (unsigned long long*) & InValue;
	Set_Internal(InName, *value, NvInt);
}

void NvParameter::Set(const char* InName, ID3D11Resource* InValue)
{
	CyberLogArgs(this, InName, InValue);
	auto value = (unsigned long long*) & InValue;
	Set_Internal(InName, *value, NvD3D11Resource);
}

void NvParameter::Set(const char* InName, ID3D12Resource* InValue)
{
	CyberLogArgs(this, InName, InValue);
	auto value = (unsigned long long*) & InValue;
	Set_Internal(InName, *value, NvD3D12Resource);
}

void NvParameter::Set(const char* InName, void* InValue)
{
	CyberLogArgs(this, InName, InValue);
	auto value = (unsigned long long*) & InValue;
	Set_Internal(InName, *value, NvVoidPtr);
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, unsigned long long* OutValue) const
{
	const auto result = Get_Internal(InName, (unsigned long long*)OutValue, NvULL);
	CyberLogArgs(this, InName, OutValue, *OutValue);
	return result;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, float* OutValue) const
{
	const auto result = Get_Internal(InName, (unsigned long long*)OutValue, NvFloat);
	CyberLogArgs(this, InName, OutValue, *OutValue);
	return result;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, double* OutValue) const
{
	const auto result = Get_Internal(InName, (unsigned long long*)OutValue, NvDouble);
	CyberLogArgs(this, InName, OutValue, *OutValue);
	return result;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, unsigned int* OutValue) const
{
	const auto result = Get_Internal(InName, (unsigned long long*)OutValue, NvUInt);
	CyberLogArgs(this, InName, OutValue, *OutValue);
	return result;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, int* OutValue) const
{
	const auto result = Get_Internal(InName, (unsigned long long*)OutValue, NvInt);
	CyberLogArgs(this, InName, OutValue, *OutValue);
	return result;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, ID3D11Resource** OutValue) const
{
	const auto result = Get_Internal(InName, (unsigned long long*)OutValue, NvD3D11Resource);
	CyberLogArgs(this, InName, OutValue, *OutValue);
	return result;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, ID3D12Resource** OutValue) const
{
	const auto result = Get_Internal(InName, (unsigned long long*)OutValue, NvD3D12Resource);
	CyberLogArgs(this, InName, OutValue, *OutValue);
	return result;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, void** OutValue) const
{
	const auto result = Get_Internal(InName, (unsigned long long*)OutValue, NvVoidPtr);
	CyberLogArgs(this, InName, OutValue, *OutValue);
	return result;
}

void NvParameter::Reset()
{
	CyberLogArgs(this);
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
		*outValueInt = 0;
		break;
	case Util::NvParameter::DLSS_Render_Subrect_Dimensions_Height:
		*outValueInt = 0;
		break;
	case Util::NvParameter::OutWidth:
		*outValueInt = renderSize.Width;
		break;
	case Util::NvParameter::OutHeight:
		*outValueInt = renderSize.Height;
		break;
	case Util::NvParameter::DLSS_Get_Dynamic_Max_Render_Width:
		*outValueInt = 0;
		break;
	case Util::NvParameter::DLSS_Get_Dynamic_Max_Render_Height:
		*outValueInt = 0;
		break;
	case Util::NvParameter::DLSS_Get_Dynamic_Min_Render_Width:
		*outValueInt = 0;
		break;
	case Util::NvParameter::DLSS_Get_Dynamic_Min_Render_Height:
		*outValueInt = 0;
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


void NvParameter::EvaluateRenderScale()
{
	enum RenderScalePriorityPreference { ratio, resolution } priority = ratio;

	float scaleRatioX = 0;
	float scaleRatioY = 0;

	unsigned int finalResX = 0;
	unsigned int finalResY = 0;

	constexpr NVSDK_NGX_Dimensions supermin = { 160,90 };

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
	
	//RTXValue = 1;

	//Static Upscale Ratio Override
	if (config->UpscaleRatioOverrideEnabled.value_or(false) && config->UpscaleRatioOverrideValue.has_value()) {
		const auto value = config->UpscaleRatioOverrideValue.value();
		scaleRatioX = value;
		scaleRatioY = value;
	}
	else {
		float overrideRatio = GetQualityOverrideRatio(PerfQualityValue, config).value_or(0);
		if (overrideRatio != 0) {
			scaleRatioX = overrideRatio;
			scaleRatioY = overrideRatio;
		}
		else {
			const FfxFsr2QualityMode fsrQualityMode = DLSS2FSR2QualityTable(PerfQualityValue);

			if (fsrQualityMode < 5) {
				ffxFsr2GetRenderResolutionFromQualityMode(&finalResX, &finalResY, windowSize.Width, windowSize.Height, fsrQualityMode);
			}
			else {
				finalResX = windowSize.Width;
				finalResY = windowSize.Height;
			}
		}
	}

	switch (priority) {
		case ratio: {
			if (scaleRatioX != 0 || scaleRatioY != 0) {
				SetRatio(scaleRatioX, scaleRatioY);
				break;
			}
			else 
				if (finalResX != 0 || finalResY != 0) {
				SetResolution(finalResX, finalResY);
				break;
			}
			else
				SetResolution(supermin.Width, supermin.Height);
			break;
		}
		case resolution: {
			if (finalResX != 0 || finalResY != 0) {
				SetResolution(finalResX, finalResY);
				break;
			}
			else 
				if (scaleRatioX != 0 || scaleRatioY != 0) {
				SetRatio(scaleRatioX, scaleRatioY);
				break;
			}
			else
				SetResolution(supermin.Width, supermin.Height);
			break;
	
		}
		default:
			SetResolution(supermin.Width, supermin.Height);
			break;
	}

	//renderSizeMin = supermin;
	renderSizeMin = renderSize;
	renderSizeMax = renderSize;
}

std::vector<NVSDK_NGX_Dimensions> generateResolutions(unsigned int maxWidth, unsigned int maxHeight, unsigned int ratioX, unsigned int ratioY) {
	CyberLogArgs(maxWidth, maxHeight, ratioX, ratioY);
	std::vector<NVSDK_NGX_Dimensions> resolutions;

	unsigned int factor = std::gcd(ratioX, ratioY);
	unsigned int ratioX1 = ratioX / factor;
	unsigned int ratioY1 = ratioY / factor;

	const unsigned int xIncrease = ratioX1;
	const unsigned int yIncrease = ratioY1;

	for (unsigned int w = ratioX1, h = ratioY1; w <= maxWidth && h <= maxHeight; w += xIncrease, h += yIncrease) {
		if (w % NvParameter::CLAMPING_VALUE == 0 && h % NvParameter::CLAMPING_VALUE == 0) {
			resolutions.push_back({ w, h });
			CyberLOGvi("Valid Resoltuion Calculated: ", w, h);
		}
	}

	return resolutions;
}

class ResolutionCache {
private:
	std::map<std::pair< long, long>, std::vector<NVSDK_NGX_Dimensions>> aspectRatioResolutions;

public:
	const std::vector<NVSDK_NGX_Dimensions>& getResolutions(long screenWidth, long screenHeight, long ratioX, long ratioY) {
		CyberLogArgs(screenWidth, screenHeight, ratioX, ratioY);


		long factor = std::gcd(ratioX, ratioY);
		long ratioX1 = ratioX / factor;
		long ratioY1 = ratioY / factor;

		std::pair<long, long> key = { ratioX1 , ratioY1 };

		auto needToGenerate = (aspectRatioResolutions.contains({ ratioX1, ratioY1}) == false);

		if (needToGenerate) {
			auto resList = generateResolutions(screenWidth * 2, screenHeight * 2, ratioX1, ratioY1);
			aspectRatioResolutions.emplace(key, resList);
		}

		return aspectRatioResolutions.at({ ratioX1, ratioY1 });
	}


};

ResolutionCache resolutionCache;

NVSDK_NGX_Dimensions findClosestResolution(const std::vector<NVSDK_NGX_Dimensions>& resolutions, long targetWidth, long targetHeight) {
	CyberLogArgs(targetWidth, targetHeight);
	NVSDK_NGX_Dimensions closestResolution = { 0, 0 };
	long minDifference = std::numeric_limits<long>::max();


	for (const auto& resolution : resolutions) {
		long inwidth = resolution.Width;
		long inheight = resolution.Height;

		long currentDifference = std::abs( targetWidth - inwidth) + std::abs( targetHeight - inheight);

		if (currentDifference < minDifference) {
			minDifference = currentDifference;
			closestResolution = resolution;
		}
	}

	return closestResolution;
}

void NvParameter::SetRatio(const float ScaleRatioX, float ScaleRatioY) {
	CyberLogArgs(ScaleRatioX, ScaleRatioY);
	long requestedWidth = windowSize.Width / ScaleRatioX;
	long requestedHeight = windowSize.Height / ScaleRatioY;

	// Calculate closest even resolutions
	long closestWidth = (requestedWidth % 2 == 0) ? requestedWidth : requestedWidth + 1;
	long closestHeight = (requestedHeight % 2 == 0) ? requestedHeight : requestedHeight + 1;

	// Update renderSize and scaleRatio with the closest even resolution
	renderSize.Width = closestWidth;
	renderSize.Height = closestHeight;
	scaleRatio.width = static_cast<float>(closestWidth) / windowSize.Width;
	scaleRatio.height = static_cast<float>(closestHeight) / windowSize.Height;
}

void NvParameter::SetResolution(const unsigned int width, const unsigned int height) {
	CyberLogArgs(width, height);

	long requestedWidth = width;
	long requestedHeight = height;

	// Calculate closest even resolutions
	long closestWidth = (requestedWidth % 2 == 0) ? requestedWidth : requestedWidth + 1;
	long closestHeight = (requestedHeight % 2 == 0) ? requestedHeight : requestedHeight + 1;

	// Update renderSize and scaleRatio with the closest even resolution
	renderSize.Width = closestWidth;
	renderSize.Height = closestHeight;
	scaleRatio.width = static_cast<float>(closestWidth) / windowSize.Width;
	scaleRatio.height = static_cast<float>(closestHeight) / windowSize.Height;
}




NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetOptimalSettingsCallback(NVSDK_NGX_Parameter* InParams)
{
	/*
	static const int limit = 6;
	static int num = 6;
	*/

	CyberLogArgs(InParams);
	auto params = static_cast<NvParameter*>(InParams);
	params->EvaluateRenderScale();
	/*
	if (num != 0) {
		float x = (float) ( (double) params->ratioUsed.width * (1.0 - (0.1 * num)) );
		float y = (float) ( (double) params->ratioUsed.height * (1.0 - (0.1 * num)) );
		params->SetRatio( x, y);
	}
	num = (num + 1) % limit;
	*/
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetStatsCallback(NVSDK_NGX_Parameter* InParams)
{
	CyberLogArgs(InParams);
	//Somehow check for allocated memory
	//Then set values: SizeInBytes, OptLevel, IsDevSnippetBranch
	return NVSDK_NGX_Result_Success;
}