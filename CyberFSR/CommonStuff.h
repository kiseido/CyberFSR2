#pragma once

namespace CyberFSR
{
	inline bool compareIgnoreCase(const std::string&, const std::string&);
	void BadThingHappened();

	namespace Timer {
		inline auto GetHighPrecisionTimeNow();
		inline auto NanoSecondsBetween(const auto& a, const auto& b);
		inline auto MilliSecondsBetween(const auto& a, const auto& b);
		long long NanoSecondsNow();
		long long MilliSecondsNow();
	}

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

			TonemapperType,

			DLSS_Render_Subrect_Dimensions_Width,
			DLSS_Render_Subrect_Dimensions_Height,

			DLSS_Get_Dynamic_Min_Render_Width,
			DLSS_Get_Dynamic_Min_Render_Height,

			DLSS_Get_Dynamic_Max_Render_Height,
			DLSS_Get_Dynamic_Max_Render_Width,

			DLSS_Input_Color_Subrect_Base_X,
			DLSS_Input_Color_Subrect_Base_Y,

			DLSS_Input_Depth_Subrect_Base_X,
			DLSS_Input_Depth_Subrect_Base_Y,

			DLSS_Input_MV_Subrect_Base_X,
			DLSS_Input_MV_Subrect_Base_Y,

			DLSS_Input_Translucency_Subrect_Base_X,
			DLSS_Input_Translucency_Subrect_Base_Y,

			DLSS_Output_Subrect_Base_X,
			DLSS_Output_Subrect_Base_Y,

			DLSS_Input_Bias_Current_Color_SubrectBase_X,
			DLSS_Input_Bias_Current_Color_SubrectBase_Y,

			DLSS_Indicator_Invert_X_Axis,
			DLSS_Indicator_Invert_Y_Axis,

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
			GBuffer_Albedo,
			GBuffer_Roughness,
			GBuffer_Metallic,
			GBuffer_Specular,
			GBuffer_Normals,
			GBuffer_Subsurface,
			GBuffer_ShadingModelId,
			GBuffer_MaterialId,
			GBuffer_Attrib_8,
			GBuffer_Attrib_9,
			GBuffer_Attrib_10,
			GBuffer_Attrib_11,
			GBuffer_Attrib_12,
			GBuffer_Attrib_13,
			GBuffer_Attrib_14,
			GBuffer_Attrib_15,
			MotionVectors3D,
			IsParticleMask,
			AnimatedTextureMask,
			DepthHighRes,
			Position_ViewSpace,
			RayTracingHitDistance,
			MotionVectorsReflection,

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