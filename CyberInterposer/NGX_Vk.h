#include "pch.h"

#ifndef CyInt_VK_INTERPOSER_H
#define CyInt_VK_INTERPOSER_H

#ifdef CyberInterposer_DO_VULKAN

#include "Common.h"

namespace CyberInterposer
{
    struct PFN_Table_NVNGX_Vulkan : public  PFN_Table_T
    {
        PFN_NVSDK_NGX_VULKAN_Init pfn_VULKAN_Init = nullptr;
        PFN_NVSDK_NGX_VULKAN_Init_Ext pfn_VULKAN_Init_Ext = nullptr;
        PFN_NVSDK_NGX_VULKAN_Init_Ext2 pfn_VULKAN_Init_Ext2 = nullptr;
        PFN_NVSDK_NGX_VULKAN_Init_ProjectID pfn_VULKAN_Init_ProjectID = nullptr;

        PFN_NVSDK_NGX_VULKAN_Shutdown pfn_VULKAN_Shutdown = nullptr;
        PFN_NVSDK_NGX_VULKAN_Shutdown1 pfn_VULKAN_Shutdown1 = nullptr;

        PFN_NVSDK_NGX_VULKAN_GetCapabilityParameters pfn_VULKAN_GetCapabilityParameters = nullptr;
        PFN_NVSDK_NGX_VULKAN_GetParameters pfn_VULKAN_GetParameters = nullptr;

        PFN_NVSDK_NGX_VULKAN_AllocateParameters pfn_VULKAN_AllocateParameters = nullptr;
        PFN_NVSDK_NGX_VULKAN_DestroyParameters pfn_VULKAN_DestroyParameters = nullptr;

        PFN_NVSDK_NGX_VULKAN_GetScratchBufferSize pfn_VULKAN_GetScratchBufferSize = nullptr;

        PFN_NVSDK_NGX_VULKAN_CreateFeature pfn_VULKAN_CreateFeature = nullptr;
        PFN_NVSDK_NGX_VULKAN_ReleaseFeature pfn_VULKAN_ReleaseFeature = nullptr;
        PFN_NVSDK_NGX_VULKAN_EvaluateFeature pfn_VULKAN_EvaluateFeature = nullptr;
        PFN_NVSDK_NGX_VULKAN_EvaluateFeature_C pfn_VULKAN_EvaluateFeature_C = nullptr;

        bool LoadDLL(HMODULE inputFile, bool populateChildren) override;
    };
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, VkInstance InInstance, VkPhysicalDevice InPD, VkDevice InDevice, PFN_vkGetInstanceProcAddr InGIPA, PFN_vkGetDeviceProcAddr InGDPA, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion);

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, VkInstance InInstance, VkPhysicalDevice InPD, VkDevice InDevice, PFN_vkGetInstanceProcAddr InGIPA, PFN_vkGetDeviceProcAddr InGDPA, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion, unsigned long long Inflags);
Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_Init_Ext2(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, VkInstance InInstance, VkPhysicalDevice InPD, VkDevice InDevice, PFN_vkGetInstanceProcAddr InGIPA, PFN_vkGetDeviceProcAddr InGDPA, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion, unsigned long long Inflags);

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, VkInstance InInstance, VkPhysicalDevice InPD, VkDevice InDevice, PFN_vkGetInstanceProcAddr InGIPA, PFN_vkGetDeviceProcAddr InGDPA, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion);

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_Shutdown(void);
Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_Shutdown1(VkDevice InDevice);

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters);
Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_GetParameters(NVSDK_NGX_Parameter** OutParameters);

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_AllocateParameters(NVSDK_NGX_Parameter** OutParameters);
Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_DestroyParameters(NVSDK_NGX_Parameter* InParameters);

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId, const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes);

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_CreateFeature(VkCommandBuffer InCmdBuffer, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle);
Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_CreateFeature1(VkDevice InDevice, VkCommandBuffer InCmdList, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle);

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_ReleaseFeature(NVSDK_NGX_Handle* InHandle);
Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_EvaluateFeature(VkCommandBuffer InCmdList, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback);

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_VULKAN_EvaluateFeature_C(VkCommandBuffer InCmdList, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback_C InCallback);


#endif

#endif