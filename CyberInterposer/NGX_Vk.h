#include "pch.h"

#ifndef CyInt_VK_INTERPOSER_H
#define CyInt_VK_INTERPOSER_H

#include "Common.h"

namespace CyberInterposer
{
    struct PFN_Table_NVNGX_Vulkan : public  PFN_Table_T
    {
        PFN_NVSDK_NGX_VULKAN_Init pfn_VULKAN_Init = nullptr;
        PFN_NVSDK_NGX_VULKAN_Init_Ext pfn_VULKAN_Init_Ext = nullptr;
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

#endif