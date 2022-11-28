#pragma once
#include "pch.h"

namespace CyberFSR
{
	enum NvParameterType
	{
		NvInt,
		NvFloat,
		NvDouble,
		NvUInt,
		NvULL,
		NvD3D11Resource,
		NvD3D12Resource,
		NvVoidPtr
	};

	enum RenderSizeBehaviour
	{
		ApplicationDefault,
		SwapWidthWithMax,
		SwapRenderOnDetectMax,
		ScaleAll
	};

	struct NvParameter : NVSDK_NGX_Parameter
	{
	private:
		//NvParameter();
	public:
		static NvParameter* GetFreshParameter();
		static NvParameter* GetFreshCapabilityParameter();
		static void RecycleParameter(NvParameter*);

		void CalcRenderDimensions();

		unsigned int Width{}, Height{}, OutWidth{}, OutHeight{}, Max_Render_Width{}, Max_Render_Height{}, Min_Render_Width{}, Min_Render_Height{}, Render_Subrect_Dimensions_Width{}, Render_Subrect_Dimensions_Height{}, DLSS_Input_Color_Subrect_Base_X{}, DLSS_Input_Color_Subrect_Base_Y{}, DLSS_Input_Depth_Subrect_Base_X{}, DLSS_Input_Depth_Subrect_Base_Y{}, DLSS_Input_MV_Subrect_Base_X{}, DLSS_Input_MV_Subrect_Base_Y{}, DLSS_Input_Translucency_Subrect_Base_X{}, DLSS_Input_Translucency_Subrect_Base_Y{}, DLSS_Output_Subrect_Base_X{}, DLSS_Output_Subrect_Base_Y{}, DLSS_Input_Bias_Current_Color_SubrectBase_X{}, DLSS_Input_Bias_Current_Color_SubrectBase_Y{};

		std::pair<unsigned int, unsigned int> ResponseRenderDimensions{};

		NVSDK_NGX_PerfQuality_Value PerfQualityValue = (NVSDK_NGX_PerfQuality_Value)-1;
		int CreationNodeMask{}, VisibilityNodeMask{}, OptLevel = 0, IsDevSnippetBranch = 0;
		float Sharpness = 1.0f;
		bool ResetRender{};
		float MVScaleX = 1.0, MVScaleY = 1.0;
		float JitterOffsetX{}, JitterOffsetY{};
		unsigned int TonemapperType{};

		long long SizeInBytes{};

		bool RTXValue{}, FreeMemOnReleaseFeature{}, DepthInverted{}, AutoExposure{}, Hdr{}, EnableSharpening{}, JitterMotion{}, LowRes{}, EnableDynamicResolution{}, EnableTexture1DUsage{ false }, SuperSampling_Available{}, EnableOutputSubrects{}, DLSS_Indicator_Invert_X_Axis{}, DLSS_Indicator_Invert_Y_Axis{};

		float FrameTimeDeltaInMsec = 0.0f;

		float PreExposure{}, ExposureScale{};


		//external Resources
		void* InputBiasCurrentColorMask{};
		void* Color{};
		void* Depth{};
		void* MotionVectors{};
		void* Output{};
		void* TransparencyMask{};
		void* ExposureTexture{};
		void* AlbedoGBuffer{};
		void* RoughnessGBuffer{};
		void* MetallicGBuffer{};
		void* SpecularGBuffer{};
		void* NormalsGBuffer{};
		void* SubsurfaceGBuffer{};
		void* ShadingModelIdGBuffer{};
		void* MaterialIdGBuffer{};
		void* Attrib8GBuffer{};
		void* Attrib9GBuffer{};
		void* Attrib10GBuffer{};
		void* Attrib11GBuffer{};
		void* Attrib12GBuffer{};
		void* Attrib13GBuffer{};
		void* Attrib14GBuffer{};
		void* Attrib15GBuffer{};
		void* MotionVectors3D{};
		void* IsParticleMask{};
		void* AnimatedTextureMask{};
		void* DepthHighRes{};
		void* Position_ViewSpace{};
		void* RayTracingHitDistance{};
		void* MotionVectorsReflection{};

		virtual void Set(const char* InName, unsigned long long InValue) override;
		virtual void Set(const char* InName, float InValue) override;
		virtual void Set(const char* InName, double InValue) override;
		virtual void Set(const char* InName, unsigned int InValue) override;
		virtual void Set(const char* InName, int InValue) override;
		virtual void Set(const char* InName, ID3D11Resource* InValue) override;
		virtual void Set(const char* InName, ID3D12Resource* InValue) override;
		virtual void Set(const char* InName, void* InValue) override;
		virtual NVSDK_NGX_Result Get(const char* InName, unsigned long long* OutValue) const override;
		virtual NVSDK_NGX_Result Get(const char* InName, float* OutValue) const override;
		virtual NVSDK_NGX_Result Get(const char* InName, double* OutValue) const override;
		virtual NVSDK_NGX_Result Get(const char* InName, unsigned int* OutValue) const override;
		virtual NVSDK_NGX_Result Get(const char* InName, int* OutValue) const override;
		virtual NVSDK_NGX_Result Get(const char* InName, ID3D11Resource** OutValue) const override;
		virtual NVSDK_NGX_Result Get(const char* InName, ID3D12Resource** OutValue) const override;
		virtual NVSDK_NGX_Result Get(const char* InName, void** OutValue) const override;
		virtual void Reset() override;

		void Set_Internal(const char* InName, unsigned long long InValue, NvParameterType ParameterType);
		NVSDK_NGX_Result Get_Internal(const char* InName, unsigned long long* OutValue, NvParameterType ParameterType) const;

		void EvaluateRenderScale();
	};
}