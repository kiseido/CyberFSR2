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
	CyberInterposer::interposer.wait_for_ready();
	CyberLogArgs(InApplicationId, InApplicationDataPath, InInstance, InPD, InDevice, InGIPA, InGDPA, InFeatureInfo, InSDKVersion, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_Vulkan.pfn_VULKAN_Init;

	if (ptr != nullptr)
	{
		auto result = ptr(InApplicationId, InApplicationDataPath, InInstance, InPD, InDevice, InGIPA, InGDPA, InFeatureInfo, InSDKVersion);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, VkInstance InInstance, VkPhysicalDevice InPD, VkDevice InDevice, PFN_vkGetInstanceProcAddr InGIPA, PFN_vkGetDeviceProcAddr InGDPA, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	CyberInterposer::interposer.wait_for_ready();
	CyberLogArgs(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InInstance, InPD, InDevice, InGIPA, InGDPA, InFeatureInfo, InSDKVersion, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_Vulkan.pfn_VULKAN_Init_ProjectID;

	if (ptr != nullptr)
	{
		auto result = ptr(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InInstance, InPD, InDevice, InGIPA, InGDPA, InFeatureInfo, InSDKVersion);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_Init_with_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, VkInstance InInstance, VkPhysicalDevice InPD, VkDevice InDevice, PFN_vkGetInstanceProcAddr InGIPA, PFN_vkGetDeviceProcAddr InGDPA, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	CyberInterposer::interposer.wait_for_ready();
	CyberLogArgs(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InInstance, InPD, InDevice, InGIPA, InGDPA, InFeatureInfo, InSDKVersion, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_Vulkan.pfn_VULKAN_Init_ProjectID;

	if (ptr != nullptr)
	{
		auto result = ptr(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InInstance, InPD, InDevice, InGIPA, InGDPA, InFeatureInfo, InSDKVersion);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_Shutdown(void)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	CyberInterposer::interposer.wait_for_ready();
	CyberLogArgs(start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_Vulkan.pfn_VULKAN_Shutdown;

	if (ptr != nullptr)
	{
		auto result = ptr();
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_Shutdown1(VkDevice InDevice)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	CyberInterposer::interposer.wait_for_ready();
	CyberLogArgs(InDevice, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_Vulkan.pfn_VULKAN_Shutdown1;

	if (ptr != nullptr)
	{
		auto result = ptr(InDevice);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_GetParameters(NVSDK_NGX_Parameter** OutParameters)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	CyberInterposer::interposer.wait_for_ready();
	CyberLogArgs(OutParameters, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_Vulkan.pfn_VULKAN_GetParameters;

	if (ptr != nullptr)
	{
		NVSDK_NGX_Parameter* originalParam = nullptr;
		auto result = ptr(&originalParam);
		CyberLOGvi(result);

		if (result == NVSDK_NGX_Result_Success && originalParam)
		{
			// Claim a wrapper from the memory pool
			auto wrappedParameter = CyberInterposer::CI_MGX_Parameter_StaticAlloc::GetParameters_depreciated.claim();

			// Set the wrapped member to the original parameter
			wrappedParameter->wrapped.param = originalParam;

			// Return the wrapped parameter
			*OutParameters = wrappedParameter;
		}
		else
		{
			*OutParameters = originalParam;
		}

		return result;
	}

	return NVSDK_NGX_Result_Fail;
}


NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_AllocateParameters(NVSDK_NGX_Parameter** OutParameters)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	CyberInterposer::interposer.wait_for_ready();
	CyberLogArgs(OutParameters, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_Vulkan.pfn_VULKAN_AllocateParameters;

	if (ptr != nullptr)
	{
		NVSDK_NGX_Parameter* originalParam = nullptr;
		auto result = ptr(&originalParam);
		CyberLOGvi(result);

		if (result == NVSDK_NGX_Result_Success && originalParam)
		{
			// Claim a wrapper from the memory pool
			auto wrappedParameter = CyberInterposer::CI_MGX_Parameter_StaticAlloc::AllocateParameters.claim();

			// Set the wrapped member to the original parameter
			wrappedParameter->wrapped.param = originalParam;

			// Return the wrapped parameter
			*OutParameters = wrappedParameter;
		}
		else
		{
			*OutParameters = originalParam;
		}

		return result;
	}

	return NVSDK_NGX_Result_Fail;
}


NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	CyberInterposer::interposer.wait_for_ready();
	CyberLogArgs(OutParameters, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_Vulkan.pfn_VULKAN_GetCapabilityParameters;

	if (ptr != nullptr)
	{
		NVSDK_NGX_Parameter* originalParam = nullptr;
		auto result = ptr(&originalParam);
		CyberLOGvi(result);

		if (result == NVSDK_NGX_Result_Success && originalParam)
		{
			// Here, let's assume that capability parameters are also claimed from the AllocateParameters pool.
			auto wrappedParameter = CyberInterposer::CI_MGX_Parameter_StaticAlloc::GetParameters_depreciated.claim();

			// Set the wrapped member to the original parameter
			wrappedParameter->wrapped.param = originalParam;

			// Return the wrapped parameter
			*OutParameters = wrappedParameter;
		}
		else
		{
			*OutParameters = originalParam;
		}

		return result;
	}

	return NVSDK_NGX_Result_Fail;
}


NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_DestroyParameters(NVSDK_NGX_Parameter* InParameters)
{
	const auto castedInParameters = (CyberInterposer::CI_Parameter*)InParameters;

	const CyberTypes::RTC start = CyberTypes::RTC(true);
	CyberInterposer::interposer.wait_for_ready();
	CyberLogArgs(InParameters, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_Vulkan.pfn_VULKAN_DestroyParameters;

	if (ptr != nullptr)
	{
		// Release the wrapper back to the pool

		// Call the original function with the unwrapped parameter
		auto result = ptr(castedInParameters->wrapped.param);
		CyberLOGvi(result);


		CyberInterposer::CI_MGX_Parameter_StaticAlloc::AllocateParameters.release(castedInParameters);
		CyberInterposer::CI_MGX_Parameter_StaticAlloc::GetParameters_depreciated.release(castedInParameters);

		return result;
	}

	return NVSDK_NGX_Result_Fail;
}


NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId, const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes)
{
	const auto castedInParameters = (CyberInterposer::CI_Parameter*)InParameters;

	const CyberTypes::RTC start = CyberTypes::RTC(true);
	CyberInterposer::interposer.wait_for_ready();
	CyberLogArgs(InFeatureId, castedInParameters, OutSizeInBytes, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_Vulkan.pfn_VULKAN_GetScratchBufferSize;

	if (ptr != nullptr)
	{
		auto result = ptr(InFeatureId, castedInParameters->wrapped.param, OutSizeInBytes);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_CreateFeature(VkCommandBuffer InCmdBuffer, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
	const auto castedInParameters = (CyberInterposer::CI_Parameter*)InParameters;

	const CyberTypes::RTC start = CyberTypes::RTC(true);
	CyberInterposer::interposer.wait_for_ready();
	CyberLogArgs(InCmdBuffer, InFeatureID, castedInParameters, OutHandle, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_Vulkan.pfn_VULKAN_CreateFeature;

	if (ptr != nullptr)
	{
		auto result = ptr(InCmdBuffer, InFeatureID, castedInParameters->wrapped.param, OutHandle);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_CreateFeature1(VkDevice InDevice, VkCommandBuffer InCmdList, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
	const auto castedInParameters = (CyberInterposer::CI_Parameter*)InParameters;

	const CyberTypes::RTC start = CyberTypes::RTC(true);
	CyberInterposer::interposer.wait_for_ready();
	CyberLogArgs(InDevice, InCmdList, InFeatureID, castedInParameters, OutHandle, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_Vulkan.pfn_VULKAN_CreateFeature1;

	if (ptr != nullptr)
	{
		auto result = ptr(InDevice, InCmdList, InFeatureID, castedInParameters->wrapped.param, OutHandle);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_ReleaseFeature(NVSDK_NGX_Handle* InHandle)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	CyberInterposer::interposer.wait_for_ready();
	CyberLogArgs(InHandle, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_Vulkan.pfn_VULKAN_ReleaseFeature;

	if (ptr != nullptr)
	{
		auto result = ptr(InHandle);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_EvaluateFeature(VkCommandBuffer InCmdList, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
	const auto castedInParameters = (CyberInterposer::CI_Parameter*)InParameters;

	const CyberTypes::RTC start = CyberTypes::RTC(true);
	CyberInterposer::interposer.wait_for_ready();
	CyberLogArgs(InCmdList, InFeatureHandle, castedInParameters, InCallback, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_Vulkan.pfn_VULKAN_EvaluateFeature;

	if (ptr != nullptr)
	{
		auto result = ptr(InCmdList, InFeatureHandle, castedInParameters->wrapped.param, InCallback);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_EvaluateFeature_C(VkCommandBuffer InCmdList, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback_C InCallback)
{
	const auto castedInParameters = (CyberInterposer::CI_Parameter*)InParameters;
	
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	CyberInterposer::interposer.wait_for_ready();
	CyberLogArgs(InCmdList, InFeatureHandle, InParameters, InCallback, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_Vulkan.pfn_VULKAN_EvaluateFeature_C;

	if (ptr != nullptr)
	{
		auto result = ptr(InCmdList, InFeatureHandle, InParameters, InCallback);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

#endif