#pragma once

namespace CyberFSR
{
	typedef unsigned long long ULongLong;
	typedef ULongLong* ULongLongPtr;

	typedef std::pair<unsigned int, unsigned int> ScreenDimensions;

	enum class Error_Resilient_Boolean : int 
	{
		ER_TRUE = ~0,
		ER_FALSE = 0,
		ON = ER_TRUE,
		OFF = ER_FALSE,
		Unknown = ER_TRUE << (sizeof(int) * 8) / 2
	};

	enum class Trinary : int
	{
		OFF = (int)Error_Resilient_Boolean::OFF,
		TBD = (int)Error_Resilient_Boolean::Unknown,
		ON = (int)Error_Resilient_Boolean::ON
	};

	enum class SharpnessRangeModifier
	{
		Normal,
		Extended
	};

	enum class ViewMethod
	{
		Config,
		Cyberpunk2077,
		RDR2
	};

	enum class UpscalingProfile
	{
		FSR2,
		DLSS2,
		DynaRes,
		FixedRes
	};

	namespace Util
	{
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
	}
}