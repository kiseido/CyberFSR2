#pragma once
#include "pch.h"

enum NvParameterType {
	NvInt,
	NvFloat,
	NvDouble,
	NvUInt,
	NvULL,
	NvD3D11Resource,
	NvD3D12Resource,
	NvVoidPtr
};

struct NvParameter : NVSDK_NGX_Parameter
{
	unsigned int Width{}, Height{}, OutWidth{}, OutHeight{};
	NVSDK_NGX_PerfQuality_Value PerfQualityValue = NVSDK_NGX_PerfQuality_Value_Balanced;
	bool RTXValue{}, FreeMemOnReleaseFeature{};
	int CreationNodeMask{}, VisibilityNodeMask{}, OptLevel{}, IsDevSnippetBranch{};
	float Sharpness = 1.0f;
	bool ResetRender{};
	float MVScaleX = 1.0, MVScaleY = 1.0;
	float JitterOffsetX{}, JitterOffsetY{};

	// gotten from `CyberFSR2-main\external\nvngx_dlss_sdk\include\nvsdk_ngx_helpers_vk.h`
	//NVSDK_NGX_VK_Feature_Eval_Params Feature;
	void* pInDepth{};
	void* pInMotionVectors{};
	float                               InJitterOffsetX{};     /* Jitter offset must be in input/render pixel space */
	float                               InJitterOffsetY{};
	NVSDK_NGX_Dimensions                InRenderSubrectDimensions{};
	/*** OPTIONAL - leave to 0/0.0f if unused ***/
	int                                 InReset{};             /* Set to 1 when scene changes completely (new level etc) */
	float                               InMVScaleX{};          /* If MVs need custom scaling to convert to pixel space */
	float                               InMVScaleY{};
	void* pInTransparencyMask{}; /* Unused/Reserved for future use */
	void* pInExposureTexture{};
	void* pInBiasCurrentColorMask{};
	NVSDK_NGX_Coordinates               InColorSubrectBase{};
	NVSDK_NGX_Coordinates               InDepthSubrectBase{};
	NVSDK_NGX_Coordinates               InMVSubrectBase{};
	NVSDK_NGX_Coordinates               InTranslucencySubrectBase{};
	NVSDK_NGX_Coordinates               InBiasCurrentColorSubrectBase{};
	NVSDK_NGX_Coordinates               InOutputSubrectBase{};
	float                               InPreExposure{};
	float                               InExposureScale{};
	int                                 InIndicatorInvertXAxis{};
	int                                 InIndicatorInvertYAxis{};

	/*** OPTIONAL - only for research purposes ***/
	//NVSDK_NGX_VK_GBuffer                GBufferSurface{};
	NVSDK_NGX_ToneMapperType            InToneMapperType{};
	void* pInMotionVectors3D{};
	void* pInIsParticleMask{}; /* to identify which pixels contains particles, essentially that are not drawn as part of base pass */
	void* pInAnimatedTextureMask{}; /* a binary mask covering pixels occupied by animated textures */
	void* pInDepthHighRes{};
	void* pInPositionViewSpace{};
	float InFrameTimeDeltaInMsec{}; /* helps in determining the amount to denoise or anti-alias based on the speed of the object from motion vector magnitudes and fps as determined by this delta */
	void* pInRayTracingHitDistance{}; /* for each effect - approximation to the amount of noise in a ray-traced color */
	void* pInMotionVectorsReflections{}; /* motion vectors of reflected objects like for mirrored surfaces */

	long long SizeInBytes{};

	bool DepthInverted{}, AutoExposure{}, Hdr{}, EnableSharpening{}, JitterMotion{}, LowRes{};

	//external Resources
	void* InputBiasCurrentColorMask{};
	void* Color{};
	void* Depth{};
	void* MotionVectors{};
	void* Output{};
	void* TransparencyMask{};
	void* ExposureTexture{};

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

