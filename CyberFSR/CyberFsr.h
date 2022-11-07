#pragma once
#include "pch.h"
#include "ViewMatrixHook.h"
#include "NvParameter.h"
#include "DebugOverlay.h"

#include <variant>

class FeatureContext;

namespace CyberFSR
{
	static NVSDK_NGX_FeatureCommonInfo FeatureCommonInfo;

	typedef std::variant<
		void*,
		std::unique_ptr<ID3D11Resource>,
		std::unique_ptr<ID3D12Resource>,
		std::unique_ptr<NVSDK_NGX_Resource_VK>,
		std::unique_ptr<NVSDK_NGX_ImageViewInfo_VK>,
		std::unique_ptr<NVSDK_NGX_BufferInfo_VK>,
		std::unique_ptr<NVSDK_NGX_Resource_VK>,
		std::unique_ptr<NVSDK_NGX_Feature>,
		std::unique_ptr<NVSDK_NGX_Parameter>
	> Cyber_Var_Ptr;
	typedef void* Cyber_Key;
	typedef Cyber_Var_Ptr Cyber_Locker;
	typedef std::map<Cyber_Key, Cyber_Locker> Cyber_Garage;

	class FeatureContext;

	static std::optional<NVSDK_NGX_EngineType> IncomingEngineType;

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
			static std::shared_ptr<CyberFsrContext> INSTANCE{ new CyberFsrContext() };
			return INSTANCE;
		}
	};

	class FeatureContext
	{
	public:
		std::unique_ptr<ViewMatrixHook> ViewMatrix = NULL;
		NVSDK_NGX_Handle Handle = { NULL };
		ID3D12Device* DxDevice = NULL;
		FfxFsr2Context FsrContext = { NULL };
		FfxFsr2ContextDescription FsrContextDescription = { NULL };
		std::unique_ptr<DebugOverlay> DebugLayer = NULL;
		std::vector<unsigned char> ScratchBuffer;

		unsigned int Width{}, Height{}, RenderWidth{}, RenderHeight{};
		NVSDK_NGX_PerfQuality_Value PerfQualityValue = NVSDK_NGX_PerfQuality_Value_Balanced;
		float Sharpness = 1.0f;
		float MVScaleX{}, MVScaleY{};
		float JitterOffsetX{}, JitterOffsetY{};
	};
}