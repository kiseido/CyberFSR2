#ifndef INTERPOSER
#define INTERPOSER

namespace Interposer
{
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_Init)(unsigned long long, const wchar_t*, ID3D11Device*, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_Init_Ext)(unsigned long long, const wchar_t*, ID3D11Device*, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version, unsigned long long);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_Shutdown)(void);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_GetParameters)(NVSDK_NGX_Parameter**);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_GetScratchBufferSize)(NVSDK_NGX_Feature, const NVSDK_NGX_Parameter*, size_t*);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_CreateFeature)(ID3D11Device*, NVSDK_NGX_Feature, NVSDK_NGX_Parameter*, NVSDK_NGX_Handle**);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_ReleaseFeature)(NVSDK_NGX_Handle*);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_EvaluateFeature)(ID3D11Device*, const NVSDK_NGX_Handle*, const NVSDK_NGX_Parameter*, PFN_NVSDK_NGX_ProgressCallback);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_GetCapabilityParameters)(NVSDK_NGX_Parameter**);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_AllocateParameters)(NVSDK_NGX_Parameter**);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_DestroyParameters)(NVSDK_NGX_Parameter*);

    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_Init_Ext)(unsigned long long, const wchar_t*, ID3D12Device*, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version, unsigned long long);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_Init)(unsigned long long, const wchar_t*, ID3D12Device*, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_Init_ProjectID)(const char*, NVSDK_NGX_EngineType, const char*, const wchar_t*, ID3D12Device*, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_Shutdown)(void);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_Shutdown1)(ID3D12Device*);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_GetParameters)(NVSDK_NGX_Parameter**);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_GetCapabilityParameters)(NVSDK_NGX_Parameter**);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_AllocateParameters)(NVSDK_NGX_Parameter**);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_DestroyParameters)(NVSDK_NGX_Parameter*);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_GetScratchBufferSize)(NVSDK_NGX_Feature, const NVSDK_NGX_Parameter*, size_t*);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_CreateFeature)(ID3D12GraphicsCommandList*, NVSDK_NGX_Feature, NVSDK_NGX_Parameter*, NVSDK_NGX_Handle**);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_ReleaseFeature)(NVSDK_NGX_Handle*);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_GetFeatureRequirements)(IDXGIAdapter*, const NVSDK_NGX_FeatureDiscoveryInfo*, NVSDK_NGX_FeatureRequirement*);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_EvaluateFeature)(ID3D12GraphicsCommandList*, const NVSDK_NGX_Handle*, const NVSDK_NGX_Parameter*, PFN_NVSDK_NGX_ProgressCallback);

    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_UpdateFeature)(const NVSDK_NGX_Application_Identifier*, const NVSDK_NGX_Feature);

    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_Init)(unsigned long long, const wchar_t*, VkInstance, VkPhysicalDevice, VkDevice, PFN_vkGetInstanceProcAddr, PFN_vkGetDeviceProcAddr, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_Init_ProjectID)(const char*, NVSDK_NGX_EngineType, const char*, const wchar_t*, VkInstance, VkPhysicalDevice, VkDevice, PFN_vkGetInstanceProcAddr, PFN_vkGetDeviceProcAddr, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_Shutdown)(void);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_GetParameters)(NVSDK_NGX_Parameter**);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_AllocateParameters)(NVSDK_NGX_Parameter**);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_GetCapabilityParameters)(NVSDK_NGX_Parameter**);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_DestroyParameters)(NVSDK_NGX_Parameter*);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_GetScratchBufferSize)(NVSDK_NGX_Feature, const NVSDK_NGX_Parameter*, size_t*);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_CreateFeature)(VkCommandBuffer, NVSDK_NGX_Feature, NVSDK_NGX_Parameter*, NVSDK_NGX_Handle**);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_ReleaseFeature)(NVSDK_NGX_Handle*);
    typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_EvaluateFeature)(VkCommandBuffer, const NVSDK_NGX_Handle*, const NVSDK_NGX_Parameter*, PFN_NVSDK_NGX_ProgressCallback);

    PFN_NVSDK_NGX_Parameter_SetULL pfn_SetULL = nullptr;
    PFN_NVSDK_NGX_Parameter_SetF pfn_SetF = nullptr;
    PFN_NVSDK_NGX_Parameter_SetD pfn_SetD = nullptr;
    PFN_NVSDK_NGX_Parameter_SetUI pfn_SetUI = nullptr;
    PFN_NVSDK_NGX_Parameter_SetI pfn_SetI = nullptr;
    PFN_NVSDK_NGX_Parameter_SetD3d11Resource pfn_SetD3d11Resource = nullptr;
    PFN_NVSDK_NGX_Parameter_SetD3d12Resource pfn_SetD3d12Resource = nullptr;
    PFN_NVSDK_NGX_Parameter_SetVoidPointer pfn_SetVoidPointer = nullptr;
    PFN_NVSDK_NGX_Parameter_GetULL pfn_GetULL = nullptr;
    PFN_NVSDK_NGX_Parameter_GetF pfn_GetF = nullptr;
    PFN_NVSDK_NGX_Parameter_GetD pfn_GetD = nullptr;
    PFN_NVSDK_NGX_Parameter_GetUI pfn_GetUI = nullptr;
    PFN_NVSDK_NGX_Parameter_GetI pfn_GetI = nullptr;
    PFN_NVSDK_NGX_Parameter_GetD3d11Resource pfn_GetD3d11Resource = nullptr;
    PFN_NVSDK_NGX_Parameter_GetD3d12Resource pfn_GetD3d12Resource = nullptr;
    PFN_NVSDK_NGX_Parameter_GetVoidPointer pfn_GetVoidPointer = nullptr;

    PFN_NVSDK_NGX_D3D11_Init pfn_D3D11_Init = nullptr;
    PFN_NVSDK_NGX_D3D11_Init_Ext pfn_D3D11_Init_Ext = nullptr;
    PFN_NVSDK_NGX_D3D11_Shutdown pfn_D3D11_Shutdown = nullptr;
    PFN_NVSDK_NGX_D3D11_GetParameters pfn_D3D11_GetParameters = nullptr;
    PFN_NVSDK_NGX_D3D11_GetScratchBufferSize pfn_D3D11_GetScratchBufferSize = nullptr;
    PFN_NVSDK_NGX_D3D11_CreateFeature pfn_D3D11_CreateFeature = nullptr;
    PFN_NVSDK_NGX_D3D11_ReleaseFeature pfn_D3D11_ReleaseFeature = nullptr;
    PFN_NVSDK_NGX_D3D11_EvaluateFeature pfn_D3D11_EvaluateFeature = nullptr;
    PFN_NVSDK_NGX_D3D11_GetCapabilityParameters pfn_D3D11_GetCapabilityParameters = nullptr;
    PFN_NVSDK_NGX_D3D11_AllocateParameters pfn_D3D11_AllocateParameters = nullptr;
    PFN_NVSDK_NGX_D3D11_DestroyParameters pfn_D3D11_DestroyParameters = nullptr;


    PFN_NVSDK_NGX_D3D12_Init_Ext pfn_D3D12_Init_Ext = nullptr;
    PFN_NVSDK_NGX_D3D12_Init pfn_D3D12_Init = nullptr;
    PFN_NVSDK_NGX_D3D12_Init_ProjectID pfn_D3D12_Init_ProjectID = nullptr;
    PFN_NVSDK_NGX_D3D12_Shutdown pfn_D3D12_Shutdown = nullptr;
    PFN_NVSDK_NGX_D3D12_Shutdown1 pfn_D3D12_Shutdown1 = nullptr;
    PFN_NVSDK_NGX_D3D12_GetParameters pfn_D3D12_GetParameters = nullptr;
    PFN_NVSDK_NGX_D3D12_GetCapabilityParameters pfn_D3D12_GetCapabilityParameters = nullptr;
    PFN_NVSDK_NGX_D3D12_AllocateParameters pfn_D3D12_AllocateParameters = nullptr;
    PFN_NVSDK_NGX_D3D12_DestroyParameters pfn_D3D12_DestroyParameters = nullptr;
    PFN_NVSDK_NGX_D3D12_GetScratchBufferSize pfn_D3D12_GetScratchBufferSize = nullptr;
    PFN_NVSDK_NGX_D3D12_CreateFeature pfn_D3D12_CreateFeature = nullptr;
    PFN_NVSDK_NGX_D3D12_ReleaseFeature pfn_D3D12_ReleaseFeature = nullptr;
    PFN_NVSDK_NGX_D3D12_GetFeatureRequirements pfn_D3D12_GetFeatureRequirements = nullptr;
    PFN_NVSDK_NGX_D3D12_EvaluateFeature pfn_D3D12_EvaluateFeature = nullptr;

    PFN_NVSDK_NGX_UpdateFeature pfn_UpdateFeature = nullptr;

    PFN_NVSDK_NGX_VULKAN_Init pfn_VULKAN_Init = nullptr;
    PFN_NVSDK_NGX_VULKAN_Init_ProjectID pfn_VULKAN_Init_ProjectID = nullptr;
    PFN_NVSDK_NGX_VULKAN_Shutdown pfn_VULKAN_Shutdown = nullptr;
    PFN_NVSDK_NGX_VULKAN_GetParameters pfn_VULKAN_GetParameters = nullptr;
    PFN_NVSDK_NGX_VULKAN_AllocateParameters pfn_VULKAN_AllocateParameters = nullptr;
    PFN_NVSDK_NGX_VULKAN_GetCapabilityParameters pfn_VULKAN_GetCapabilityParameters = nullptr;
    PFN_NVSDK_NGX_VULKAN_DestroyParameters pfn_VULKAN_DestroyParameters = nullptr;
    PFN_NVSDK_NGX_VULKAN_GetScratchBufferSize pfn_VULKAN_GetScratchBufferSize = nullptr;
    PFN_NVSDK_NGX_VULKAN_CreateFeature pfn_VULKAN_CreateFeature = nullptr;
    PFN_NVSDK_NGX_VULKAN_ReleaseFeature pfn_VULKAN_ReleaseFeature = nullptr;
    PFN_NVSDK_NGX_VULKAN_EvaluateFeature pfn_VULKAN_EvaluateFeature = nullptr;

    // Function that loads the dependent DLL and retrieves function pointers
    bool LoadDependentDLL(LPCWSTR inputFileName);
};

#endif
