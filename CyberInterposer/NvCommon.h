#include "pch.h"

struct NvParameter : NVSDK_NGX_Parameter
{
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
};