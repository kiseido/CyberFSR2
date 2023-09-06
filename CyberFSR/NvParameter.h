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

#include <stdexcept>
#include <array>

template <typename ResourceType>
struct DLSSResources {
	enum Field {
		Color_enum,
		Output_enum,
		Depth_enum,
		MotionVectors_enum,
		TransparencyMask_enum,
		ExposureTexture_enum,
		BiasCurrentColorMask_enum,
		GBufferAlbedo_enum,
		GBufferRoughness_enum,
		GBufferMetallic_enum,
		GBufferSpecular_enum,
		GBufferSubsurface_enum,
		GBufferNormals_enum,
		GBufferShadingModelId_enum,
		GBufferMaterialId_enum,
		GBufferAttrib0_enum, 
		GBufferAttrib1_enum,
		GBufferAttrib2_enum,
		GBufferAttrib3_enum,
		GBufferAttrib4_enum,
		GBufferAttrib5_enum,
		GBufferAttrib6_enum,
		GBufferAttrib7_enum,
		GBufferAttrib8_enum,
		GBufferAttrib9_enum,
		GBufferAttrib10_enum,
		GBufferAttrib11_enum,
		GBufferAttrib12_enum,
		GBufferAttrib13_enum,
		GBufferAttrib14_enum,
		GBufferAttrib15_enum,
		MotionVectors3D_enum,
		IsParticleMask_enum,
		AnimatedTextureMask_enum,
		DepthHighRes_enum,
		MotionVectorsReflection_enum,
		length_enum
	};

	std::array<ResourceType, length_enum> resources;

	ResourceType& Color() { return resources[Field::Color_enum]; }
	ResourceType& Output() { return resources[Field::Output_enum]; }
	ResourceType& Depth() { return resources[Field::Depth_enum]; }
	ResourceType& MotionVectors() { return resources[Field::MotionVectors_enum]; }
	ResourceType& TransparencyMask() { return resources[Field::TransparencyMask_enum]; }
	ResourceType& ExposureTexture() { return resources[Field::ExposureTexture_enum]; }
	ResourceType& BiasCurrentColorMask() { return resources[Field::BiasCurrentColorMask_enum]; }
	ResourceType& GBufferAlbedo() { return resources[Field::GBufferAlbedo_enum]; }
	ResourceType& GBufferRoughness() { return resources[Field::GBufferRoughness_enum]; }
	ResourceType& GBufferMetallic() { return resources[Field::GBufferMetallic_enum]; }
	ResourceType& GBufferSpecular() { return resources[Field::GBufferSpecular_enum]; }
	ResourceType& GBufferSubsurface() { return resources[Field::GBufferSubsurface_enum]; }
	ResourceType& GBufferNormals() { return resources[Field::GBufferNormals_enum]; }
	ResourceType& GBufferShadingModelId() { return resources[Field::GBufferShadingModelId_enum]; }
	ResourceType& GBufferMaterialId() { return resources[Field::GBufferMaterialId_enum]; }
	ResourceType& GBufferAttrib0() { return resources[Field::GBufferAttrib0_enum]; }
	ResourceType& GBufferAttrib1() { return resources[Field::GBufferAttrib1_enum]; }
	ResourceType& GBufferAttrib2() { return resources[Field::GBufferAttrib2_enum]; }
	ResourceType& GBufferAttrib3() { return resources[Field::GBufferAttrib3_enum]; }
	ResourceType& GBufferAttrib4() { return resources[Field::GBufferAttrib4_enum]; }
	ResourceType& GBufferAttrib5() { return resources[Field::GBufferAttrib5_enum]; }
	ResourceType& GBufferAttrib6() { return resources[Field::GBufferAttrib6_enum]; }
	ResourceType& GBufferAttrib7() { return resources[Field::GBufferAttrib7_enum]; }
	ResourceType& GBufferAttrib8() { return resources[Field::GBufferAttrib8_enum]; }
	ResourceType& GBufferAttrib9() { return resources[Field::GBufferAttrib9_enum]; }
	ResourceType& GBufferAttrib10() { return resources[Field::GBufferAttrib10_enum]; }
	ResourceType& GBufferAttrib11() { return resources[Field::GBufferAttrib11_enum]; }
	ResourceType& GBufferAttrib12() { return resources[Field::GBufferAttrib12_enum]; }
	ResourceType& GBufferAttrib13() { return resources[Field::GBufferAttrib13_enum]; }
	ResourceType& GBufferAttrib14() { return resources[Field::GBufferAttrib14_enum]; }
	ResourceType& GBufferAttrib15() { return resources[Field::GBufferAttrib15_enum]; }
	ResourceType& MotionVectors3D() { return resources[Field::MotionVectors3D_enum]; }
	ResourceType& IsParticleMask() { return resources[Field::IsParticleMask_enum]; }
	ResourceType& AnimatedTextureMask() { return resources[Field::AnimatedTextureMask_enum]; }
	ResourceType& DepthHighRes() { return resources[Field::DepthHighRes_enum]; }
	ResourceType& MotionVectorsReflection() { return resources[Field::MotionVectorsReflection_enum]; }

	ResourceType& operator[](size_t index) {
		if (index >= Field::length_enum) {
			throw std::out_of_range("Invalid index");
		}
		return resources[index];
	}

	const ResourceType& operator[](size_t index) const {
		if (index >= Field::length_enum) {
			throw std::out_of_range("Invalid index");
		}
		return resources[index];
	}
};

typedef DLSSResources<ID3D12Resource*> D3D_DLSSResources;
typedef DLSSResources<NVSDK_NGX_Resource_VK*> VK_DLSSResources;


struct DLSS_Settings {
	NVSDK_NGX_Dimensions renderSize;

	NVSDK_NGX_Dimensions renderSizeMax;

	NVSDK_NGX_Dimensions renderSizeMin;

	bool RTXValue{}, FreeMemOnReleaseFeature{};
	int CreationNodeMask{}, VisibilityNodeMask{}, OptLevel{}, IsDevSnippetBranch{};
	float Sharpness = 1.0f;
	bool ResetRender{};
	float MVScaleX = 1.0, MVScaleY = 1.0;
	float JitterOffsetX{}, JitterOffsetY{};

	bool DepthInverted{}, AutoExposure{}, Hdr{}, EnableSharpening{}, JitterMotion{}, LowRes{};
};

enum ReactiveMaskState {
	Game_Defined,
	Auto_Mask,
	Disabled
};

struct NvParameter : NVSDK_NGX_Parameter
{
	const static unsigned int CLAMPING_VALUE = 2;

	struct { float width = 1; float height = 1; } scaleRatio;

	NVSDK_NGX_Dimensions screenSize;

	NVSDK_NGX_Dimensions windowSize;

	NVSDK_NGX_Dimensions renderSize;

	NVSDK_NGX_Dimensions renderSizeMax;

	NVSDK_NGX_Dimensions renderSizeMin;

	NVSDK_NGX_PerfQuality_Value PerfQualityValue = NVSDK_NGX_PerfQuality_Value_Balanced;
	bool RTXValue{}, FreeMemOnReleaseFeature{};
	int CreationNodeMask{}, VisibilityNodeMask{}, OptLevel{}, IsDevSnippetBranch{};
	float Sharpness = 1.0f;
	bool ResetRender{};
	float MVScaleX = 1.0, MVScaleY = 1.0;
	float JitterOffsetX{}, JitterOffsetY{};

	long long SizeInBytes{};

	bool DepthInverted{}, AutoExposure{}, Hdr{}, EnableSharpening{}, JitterMotion{}, LowRes{};

	DLSSResources<void*> Input_Resources;
	DLSS_Settings Input_Settings;

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

	inline void Set_Internal(const char* InName, unsigned long long InValue, NvParameterType ParameterType);
	inline NVSDK_NGX_Result Get_Internal(const char* InName, unsigned long long* OutValue, NvParameterType ParameterType) const;

	void EvaluateRenderScale();

	void SetRatio(const float x, const float y);
	void SetResolution(const unsigned int width, const unsigned int height);

	/**
	template <typename T>
	inline constexpr T& Cast(const auto& Parameter)
	{
		return *((T*)&Parameter);
	}
	**/

	std::vector<std::shared_ptr<NvParameter>> Params;

	__declspec(noinline) NvParameter* AllocateParameters()
	{
		const auto ptr = std::make_shared<NvParameter>();
		Params.push_back(ptr);
		return ptr.get();
	}

	__declspec(noinline) void DeleteParameters(NvParameter* param)
	{
		auto it = std::find_if(Params.begin(), Params.end(),
			[param](const auto& p) { return p.get() == param; });
		Params.erase(it);
	}

	static std::shared_ptr<NvParameter> instance()
	{
		static std::shared_ptr<NvParameter> INSTANCE { std::make_shared<NvParameter>() };
		return INSTANCE;
	}
};
