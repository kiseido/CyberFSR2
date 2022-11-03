#include "pch.h"
#include "Config.h"
#include "Util.h"
#include "NvParameter.h"
#include "CyberFsr.h"

constexpr float NO_VALUEf = -128.125;
constexpr int NO_VALUEi = -128;

namespace CyberFSR
{
	void NvParameter::Set(const char* InName, unsigned long long InValue)
	{
		constexpr NvParameterType nvType = NvULL;
		Set_Internal(InName, (ULongLong)InValue, nvType);
	}

	void NvParameter::Set(const char* InName, float InValue)
	{
		constexpr NvParameterType nvType = NvFloat;
		Set_Internal(InName, (ULongLong)InValue, nvType);
	}

	void NvParameter::Set(const char* InName, double InValue)
	{
		constexpr NvParameterType nvType = NvDouble;
		Set_Internal(InName, (ULongLong)InValue, nvType);
	}

	void NvParameter::Set(const char* InName, unsigned int InValue)
	{
		constexpr NvParameterType nvType = NvUInt;
		Set_Internal(InName, (ULongLong)InValue, nvType);
	}

	void NvParameter::Set(const char* InName, int InValue)
	{
		constexpr NvParameterType nvType = NvInt;
		Set_Internal(InName, (ULongLong)InValue, nvType);
	}

	void NvParameter::Set(const char* InName, ID3D11Resource* InValue)
	{
		constexpr NvParameterType nvType = NvD3D11Resource;
		Set_Internal(InName, (ULongLong)InValue, nvType);
	}

	void NvParameter::Set(const char* InName, ID3D12Resource* InValue)
	{
		constexpr NvParameterType nvType = NvD3D12Resource;
		Set_Internal(InName, (ULongLong)InValue, nvType);
	}

	void NvParameter::Set(const char* InName, void* InValue)
	{
		constexpr NvParameterType nvType = NvVoidPtr;
		Set_Internal(InName, (ULongLong)InValue, nvType);
	}

	NVSDK_NGX_Result NvParameter::Get(const char* InName, unsigned long long* OutValue) const
	{
		constexpr NvParameterType nvType = NvULL;
		return Get_Internal(InName, (ULongLongPtr)OutValue, nvType);
	}

	NVSDK_NGX_Result NvParameter::Get(const char* InName, float* OutValue) const
	{
		constexpr NvParameterType nvType = NvFloat;
		return Get_Internal(InName, (ULongLongPtr)OutValue, nvType);
	}

	NVSDK_NGX_Result NvParameter::Get(const char* InName, double* OutValue) const
	{
		constexpr NvParameterType nvType = NvDouble;
		return Get_Internal(InName, (ULongLongPtr)OutValue, nvType);
	}

	NVSDK_NGX_Result NvParameter::Get(const char* InName, unsigned int* OutValue) const
	{
		constexpr NvParameterType nvType = NvUInt;
		return Get_Internal(InName, (ULongLongPtr)OutValue, nvType);
	}

	NVSDK_NGX_Result NvParameter::Get(const char* InName, int* OutValue) const
	{
		constexpr NvParameterType nvType = NvInt;
		return Get_Internal(InName, (ULongLongPtr)OutValue, nvType);
	}

	NVSDK_NGX_Result NvParameter::Get(const char* InName, ID3D11Resource** OutValue) const
	{
		constexpr NvParameterType nvType = NvD3D11Resource;
		return Get_Internal(InName, (ULongLongPtr)OutValue, nvType);
	}

	NVSDK_NGX_Result NvParameter::Get(const char* InName, ID3D12Resource** OutValue) const
	{
		constexpr NvParameterType nvType = NvD3D12Resource;
		return Get_Internal(InName, (ULongLongPtr)OutValue, nvType);
	}

	NVSDK_NGX_Result NvParameter::Get(const char* InName, void** OutValue) const
	{
		constexpr NvParameterType nvType = NvVoidPtr;
		return Get_Internal(InName, (ULongLongPtr)OutValue, nvType);
	}

void NvParameter::Reset()
{
}

	void NvParameter::Set_Internal(const char* InName, unsigned long long InValue, NvParameterType ParameterType)
	{
#define inValueFloat (*((float*)InValue))
#define inValueInt (*((int*)InValue))
#define inValueDouble (*((double*)InValue))
#define inValueUInt (*((unsigned int*)InValue))
#define inValueULL (*((unsigned long long*)InValue))
		//Includes DirectX Resources
#define inValuePtr (*((void**)InValue))

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
			Hdr = inValueInt & NVSDK_NGX_DLSS_Feature_Flags_IsHDR;
			LowRes = inValueInt & NVSDK_NGX_DLSS_Feature_Flags_MVLowRes;
			JitterMotion = inValueInt & NVSDK_NGX_DLSS_Feature_Flags_MVJittered;
			DepthInverted = inValueInt & NVSDK_NGX_DLSS_Feature_Flags_DepthInverted;
			EnableSharpening = inValueInt & NVSDK_NGX_DLSS_Feature_Flags_DoSharpening;
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

#undef inValueFloat
#undef inValueInt
#undef inValueDouble
#undef inValueUInt
#undef inValueULL
#undef inValuePtr
	}

	NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetOptimalSettingsCallback(NVSDK_NGX_Parameter* InParams);
	NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetStatsCallback(NVSDK_NGX_Parameter* InParams);

NVSDK_NGX_Result NvParameter::Get_Internal(const char* InName, unsigned long long* OutValue, NvParameterType ParameterType) const
{
	const Util::NvParameter inParameter = Util::NvParameterToEnum(InName);

#define outValueFloat *((float*)OutValue)
#define outValueInt *((int*)OutValue)
#define outValueDouble *((double*)OutValue)
#define outValueUInt *((unsigned int*)OutValue)
#define outValueULL *OutValue
		//Includes DirectX Resources
#define outValuePtr *((void**)OutValue)

		switch (inParameter)
		{
		case Util::NvParameter::Sharpness:
			outValueFloat = Sharpness;
			break;
		case Util::NvParameter::SuperSampling_Available:
		case Util::NvParameter::SuperSampling_Available_E:
			outValueInt = true;
			break;
		case Util::NvParameter::SuperSampling_FeatureInitResult:
			outValueInt = NVSDK_NGX_Result_Success;
			break;
		case Util::NvParameter::SuperSampling_NeedsUpdatedDriver:
			outValueInt = 0;
			break;
		case Util::NvParameter::SuperSampling_MinDriverVersionMinor:
			outValueInt = 0;
			break;
		case Util::NvParameter::SuperSampling_MinDriverVersionMajor:
			outValueInt = 0;
			break;
		case Util::NvParameter::DLSS_Render_Subrect_Dimensions_Width:
			outValueInt = Width;
			break;
		case Util::NvParameter::DLSS_Render_Subrect_Dimensions_Height:
			outValueInt = Height;
			break;
		case Util::NvParameter::OutWidth:
			outValueInt = OutWidth;
			break;
		case Util::NvParameter::OutHeight:
			outValueInt = OutHeight;
			break;
		case Util::NvParameter::DLSS_Get_Dynamic_Max_Render_Width:
			outValueInt = Width;
			break;
		case Util::NvParameter::DLSS_Get_Dynamic_Max_Render_Height:
			outValueInt = Height;
			break;
		case Util::NvParameter::DLSS_Get_Dynamic_Min_Render_Width:
			outValueInt = OutWidth;
			break;
		case Util::NvParameter::DLSS_Get_Dynamic_Min_Render_Height:
			outValueInt = OutHeight;
			break;
		case Util::NvParameter::DLSSOptimalSettingsCallback:
			outValuePtr = NVSDK_NGX_DLSS_GetOptimalSettingsCallback;
			break;
		case Util::NvParameter::DLSSGetStatsCallback:
			outValuePtr = NVSDK_NGX_DLSS_GetStatsCallback;
			break;
		case Util::NvParameter::SizeInBytes:
			outValueULL = 0x1337; //Dummy value
			break;
		case Util::NvParameter::OptLevel:
		case Util::NvParameter::OptLevel_E:
			outValueInt = 0; //Dummy value
			break;
		case Util::NvParameter::IsDevSnippetBranch:
		case Util::NvParameter::IsDevSnippetBranch_E:
			outValueInt = 0; //Dummy value
			break;
		default:
#ifdef _DEBUG
			return NVSDK_NGX_Result_Fail;
#else
			return NVSDK_NGX_Result_Success; //lie and hope for the best
#endif
		}
#undef outValueFloat
#undef outValueInt
#undef outValueDouble
#undef outValueUInt
#undef outValueULL
#undef outValuePtr
		return NVSDK_NGX_Result_Success;
	}

	// EvaluateRenderScale helper
	inline float FSR2QualityTable(const NVSDK_NGX_PerfQuality_Value& input)
	{
		float output = NO_VALUEf;

		switch (input)
		{
		case NVSDK_NGX_PerfQuality_Value_UltraPerformance:
			output = 3.0f;
			break;
		case NVSDK_NGX_PerfQuality_Value_MaxPerf:
			output = 2.0f;
			break;
		case NVSDK_NGX_PerfQuality_Value_Balanced:
			output = 1.7f;
			break;
		case NVSDK_NGX_PerfQuality_Value_MaxQuality:
			output = 1.5f;
			break;
		case NVSDK_NGX_PerfQuality_Value_UltraQuality:
			break;
		}
		return output;
	}

	// EvaluateRenderScale helper
	inline float DLSS2QualityTable(const NVSDK_NGX_PerfQuality_Value& input)
	{
		float output = NO_VALUEf;

		switch (input)
		{
		case NVSDK_NGX_PerfQuality_Value_UltraPerformance:
			output = 3.0f;
			break;
		case NVSDK_NGX_PerfQuality_Value_MaxPerf:
			output = 2.0f;
			break;
		case NVSDK_NGX_PerfQuality_Value_Balanced:
			output = 1.7f;
			break;
		case NVSDK_NGX_PerfQuality_Value_MaxQuality:
			output = 1.5f;
			break;
		case NVSDK_NGX_PerfQuality_Value_UltraQuality:
			output = 1.3f;
			break;
		}
		return output;
	}

	// EvaluateRenderScale helper
	inline FfxFsr2QualityMode DLSS2FSR2QualityTable(const NVSDK_NGX_PerfQuality_Value& input)
	{
		int output = NO_VALUEi;

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
			break;
		}
		return (FfxFsr2QualityMode)output;
	}

	// EvaluateRenderScale helper
	inline float GetQualityOverrideRatio(const NVSDK_NGX_PerfQuality_Value& input, const std::shared_ptr<Config>& config)
	{
		float output = NO_VALUEf;

		switch (input)
		{
		case NVSDK_NGX_PerfQuality_Value_UltraPerformance:
			output = config->QualityRatio_UltraPerformance.value_or(NO_VALUEf);
			break;
		case NVSDK_NGX_PerfQuality_Value_MaxPerf:
			output = config->QualityRatio_Performance.value_or(NO_VALUEf);
			break;
		case NVSDK_NGX_PerfQuality_Value_Balanced:
			output = config->QualityRatio_Balanced.value_or(NO_VALUEf);
			break;
		case NVSDK_NGX_PerfQuality_Value_MaxQuality:
			output = config->QualityRatio_Quality.value_or(NO_VALUEf);
			break;
		case NVSDK_NGX_PerfQuality_Value_UltraQuality:
			output = config->QualityRatio_UltraQuality.value_or(NO_VALUEf);
			break;
		default:
			// no correlated value, add some logging?
			break;
		}
		return output;
	}

	typedef std::pair<unsigned int, unsigned int> ScreenDimensions;


	inline ScreenDimensions CalcSame(const auto& Width, const auto& Height, const auto& Division_Ratio) {
		// do a single division now to save on calc time later
		const auto resolution_Ratio = 1.0f / Division_Ratio;

		ScreenDimensions output = { 0,0 };

		// Multiply is faster than divide
		const unsigned int computedHeight = std::lround(Height * resolution_Ratio);
		// Multiply is faster than divide
		const unsigned int computedWidth = std::lround(Width * resolution_Ratio);

		output.first = computedHeight;
		output.second = computedWidth;
		return output;
	}

	inline ScreenDimensions CalcDifferent(const auto& Width, const auto& Height, const auto& Width_Division_Ratio, const auto& Height_Division_Ratio) {
		ScreenDimensions output = { 0,0 };
		const unsigned int computedHeight = std::lround(Height / Height_Division_Ratio);
		const unsigned int computedWidth = std::lround(Width / Width_Division_Ratio);

		output.first = computedHeight;
		output.second = computedWidth;
		return output;
	}

	inline ScreenDimensions Switcher(const std::shared_ptr<Config>& InConfig, const NvParameter* InNvParameter, const UpscalingProfile& InProfile)
	{
		// multiply is generally significantly faster than divide, so store ratio as a multiple
		// constexpr should occur at compile-time, saving on division later
		// double is vastly more accurate than float, use it curing compute when useful and cheap

		ScreenDimensions output = {0,0};

		switch (InProfile)
		{
			case UpscalingProfile::DLSS2:
			{
				float QualityRatio = GetQualityOverrideRatio(InNvParameter->PerfQualityValue, InConfig);

				if (QualityRatio == NO_VALUEf)
					QualityRatio = DLSS2QualityTable(InNvParameter->PerfQualityValue);

				output = CalcSame(InNvParameter->Width, InNvParameter->Height, QualityRatio);
			}
				break;
			case UpscalingProfile::FSR2:
			{
				float QualityRatio = GetQualityOverrideRatio(InNvParameter->PerfQualityValue, InConfig);
				if (QualityRatio != NO_VALUEf)
				{
					output = CalcSame(InNvParameter->Width, InNvParameter->Height, QualityRatio);
				} 
				else
				{
					FfxFsr2QualityMode fsrQualityMode = DLSS2FSR2QualityTable(InNvParameter->PerfQualityValue);

					if (fsrQualityMode != NO_VALUEi)
					{
						const FfxErrorCode err = ffxFsr2GetRenderResolutionFromQualityMode(&output.second, &output.first, InNvParameter->Width, InNvParameter->Height, fsrQualityMode);
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
				}
			}
				break;
			case UpscalingProfile::DynaRes:
				break;
			case UpscalingProfile::Fixed:
				break;
			default:
				// no correlated value, add some logging?
				break;
		}
		return output;
	}

	void NvParameter::EvaluateRenderScale()
	{
		// percentage of the screen size to use as render size, in decimal. 
		// 1.0 : 100%
		// 0.8 :   80%
		//
		constexpr auto defaultRatioVertical = 1.0f;
		// percentage of the screen size to use as render size, in decimal. 
		// 1.0 : 100%
		// 0.8 :   80%
		//
		constexpr auto defaultRatioHorizontal = 1.0f;

	std::shared_ptr<Config> config = CyberFsrContext::instance()->MyConfig;

		auto dimensions = Switcher(config, this, config->UpscalerProfile);

		if (dimensions.second == 0 || dimensions.first == 0) {
			OutHeight = std::lround(Height * defaultRatioVertical);
			OutWidth = std::lround(Width * defaultRatioHorizontal);
		}
		else {
			OutHeight = dimensions.first;
			OutWidth = dimensions.second;
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