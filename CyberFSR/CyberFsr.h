#pragma once
#include "pch.h"
#include "ViewMatrixHook.h"
#include "NvParameter.h"
#include "DebugOverlay.h"

#include <variant>

using Cyber_Var_Ptr = std::variant<
	void*,
	std::unique_ptr<ID3D11Resource>,
	std::unique_ptr<ID3D12Resource>,
	std::unique_ptr<NVSDK_NGX_Resource_VK>,
	std::unique_ptr<NVSDK_NGX_ImageViewInfo_VK>,
	std::unique_ptr<NVSDK_NGX_BufferInfo_VK>,
	std::unique_ptr<NVSDK_NGX_Resource_VK>,
	std::unique_ptr<NVSDK_NGX_Feature>,
	std::unique_ptr<NVSDK_NGX_Parameter>
>;
using Cyber_Key = void*;
using Cyber_Locker = std::optional<Cyber_Var_Ptr>;
using Cyber_Garage = std::map<Cyber_Key, Cyber_Locker>;

class FeatureContext;

//Global Context
class CyberFsrContext
{
	CyberFsrContext();
public:
	std::shared_ptr<Config> MyConfig;

	VkDevice VulkanDevice;
	VkInstance VulkanInstance;
	VkPhysicalDevice VulkanPhysicalDevice;

	std::vector<std::unique_ptr<NvParameter>> Parameters;
	NvParameter* AllocateParameter();
	void DeleteParameter(NvParameter* parameter);

	std::unordered_map <unsigned int, std::unique_ptr<FeatureContext>> Contexts;
	FeatureContext* CreateContext();
	void DeleteContext(NVSDK_NGX_Handle* handle);

	static std::shared_ptr<CyberFsrContext> instance()
	{
		static std::shared_ptr<CyberFsrContext> INSTANCE{new CyberFsrContext()};
		return INSTANCE;
	}
};

class FeatureContext
{
public:
	std::unique_ptr<ViewMatrixHook> ViewMatrix;
	NVSDK_NGX_Handle Handle;
	ID3D12Device* DxDevice;
	FfxFsr2Context FsrContext;
	FfxFsr2ContextDescription FsrContextDescription;
	std::unique_ptr<DebugOverlay> DebugLayer;
	std::vector<unsigned char> ScratchBuffer;

	unsigned int Width{}, Height{}, RenderWidth{}, RenderHeight{};
	NVSDK_NGX_PerfQuality_Value PerfQualityValue = NVSDK_NGX_PerfQuality_Value_Balanced;
	float Sharpness = 1.0f;
	float MVScaleX{}, MVScaleY{};
	float JitterOffsetX{}, JitterOffsetY{};
};