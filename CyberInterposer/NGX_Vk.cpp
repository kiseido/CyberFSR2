#include "pch.h"
#include "NGX_Interposer.h"

#ifdef CyberInterposer_DO_VULKAN

namespace CyberInterposer {
	bool PFN_Table_NVNGX_Vulkan::LoadDLL(HMODULE hModule, bool populateChildren)
	{
		CyberLogArgs(hModule, populateChildren);

		if (hModule == nullptr)
		{
			return false;
		}

		bool foundFunctions = true;

		foundFunctions &= LoadFunction(pfn_VULKAN_Init, hModule, "NVSDK_NGX_VULKAN_Init");
		foundFunctions &= LoadFunction(pfn_VULKAN_Init_Ext, hModule, "NVSDK_NGX_VULKAN_Init_Ext");
		foundFunctions &= LoadFunction(pfn_VULKAN_Init_Ext2, hModule, "NVSDK_NGX_VULKAN_Init_Ext2");
		foundFunctions &= LoadFunction(pfn_VULKAN_Init_ProjectID, hModule, "NVSDK_NGX_VULKAN_Init_ProjectID");
		foundFunctions &= LoadFunction(pfn_VULKAN_Shutdown, hModule, "NVSDK_NGX_VULKAN_Shutdown");
		foundFunctions &= LoadFunction(pfn_VULKAN_Shutdown1, hModule, "NVSDK_NGX_VULKAN_Shutdown1");
		foundFunctions &= LoadFunction(pfn_VULKAN_GetCapabilityParameters, hModule, "NVSDK_NGX_VULKAN_GetCapabilityParameters");
		foundFunctions &= LoadFunction(pfn_VULKAN_GetParameters, hModule, "NVSDK_NGX_VULKAN_GetParameters");
		foundFunctions &= LoadFunction(pfn_VULKAN_GetScratchBufferSize, hModule, "NVSDK_NGX_VULKAN_GetScratchBufferSize");
		foundFunctions &= LoadFunction(pfn_VULKAN_CreateFeature, hModule, "NVSDK_NGX_VULKAN_CreateFeature");
		foundFunctions &= LoadFunction(pfn_VULKAN_ReleaseFeature, hModule, "NVSDK_NGX_VULKAN_ReleaseFeature");
		foundFunctions &= LoadFunction(pfn_VULKAN_EvaluateFeature, hModule, "NVSDK_NGX_VULKAN_EvaluateFeature");
		foundFunctions &= LoadFunction(pfn_VULKAN_EvaluateFeature_C, hModule, "NVSDK_NGX_VULKAN_EvaluateFeature_C");
		foundFunctions &= LoadFunction(pfn_VULKAN_AllocateParameters, hModule, "NVSDK_NGX_VULKAN_AllocateParameters");
		foundFunctions &= LoadFunction(pfn_VULKAN_DestroyParameters, hModule, "NVSDK_NGX_VULKAN_DestroyParameters");

		return foundFunctions;
	}
}



Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, VkInstance InInstance, VkPhysicalDevice InPD, VkDevice InDevice, PFN_vkGetInstanceProcAddr InGIPA, PFN_vkGetDeviceProcAddr InGDPA, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InApplicationId, InApplicationDataPath, InInstance, InPD, InDevice, InGIPA, InGDPA, InFeatureInfo, InSDKVersion, start);

	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, VkInstance InInstance, VkPhysicalDevice InPD, VkDevice InDevice, PFN_vkGetInstanceProcAddr InGIPA, PFN_vkGetDeviceProcAddr InGDPA, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InInstance, InPD, InDevice, InGIPA, InGDPA, InFeatureInfo, InSDKVersion, start);

	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_Init_with_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, VkInstance InInstance, VkPhysicalDevice InPD, VkDevice InDevice, PFN_vkGetInstanceProcAddr InGIPA, PFN_vkGetDeviceProcAddr InGDPA, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InInstance, InPD, InDevice, InGIPA, InGDPA, InFeatureInfo, InSDKVersion, start);

	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_Shutdown(void)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(start);

	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_Shutdown1(VkDevice InDevice)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InDevice, start);

	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_GetParameters(NVSDK_NGX_Parameter** OutParameters)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(OutParameters, start);

	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_AllocateParameters(NVSDK_NGX_Parameter** OutParameters)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(OutParameters, start);

	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(OutParameters, start);

	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_DestroyParameters(NVSDK_NGX_Parameter* InParameters)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InParameters, start);

	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId, const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InFeatureId, InParameters, OutSizeInBytes, start);

	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_CreateFeature(VkCommandBuffer InCmdBuffer, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InCmdBuffer, InFeatureID, InParameters, OutHandle, start);

	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_CreateFeature1(VkDevice InDevice, VkCommandBuffer InCmdList, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InDevice, InCmdList, InFeatureID, InParameters, OutHandle, start);

	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_ReleaseFeature(NVSDK_NGX_Handle* InHandle)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InHandle, start);

	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_EvaluateFeature(VkCommandBuffer InCmdList, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InCmdList, InFeatureHandle, InParameters, InCallback, start);

	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_EvaluateFeature_C(VkCommandBuffer InCmdList, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback_C InCallback)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InCmdList, InFeatureHandle, InParameters, InCallback, start);

	return NVSDK_NGX_Result_Success;
}

#endif