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


struct NvParameter : public NVSDK_NGX_Parameter
{
	CyberStorage::Cyber_Resource_Pointer NGX_Feature_Create_Params;
	CyberStorage::Cyber_Resource_Pointer NGX_XX_DLSS_Eval_Params;
	CyberStorage::Cyber_Resource_Pointer NGX_XX_Feature_Eval_Params;
	CyberStorage::Cyber_Resource_Pointer NGX_DLDenoise_Create_Params;
	
	bool RTXValue{}, FreeMemOnReleaseFeature{};
	int CreationNodeMask{}, VisibilityNodeMask{}, OptLevel{}, IsDevSnippetBranch{};

	unsigned long long SizeInBytes{};

	bool DepthInverted{}, AutoExposure{}, Hdr{}, EnableSharpening{}, JitterMotion{}, LowRes{};

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

