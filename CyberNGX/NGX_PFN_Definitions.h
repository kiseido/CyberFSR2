#include "pch.h"

#ifndef PFN_DEFINITIONS
#define PFN_DEFINITIONS



#include <d3d11.h>
#include <d3dcompiler.h>

#include <d3d12.h>

#include <vulkan/vulkan.hpp>


typedef void(NVSDK_CONV* PFN_NVSDK_NGX_Reset)(NVSDK_NGX_Parameter*);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_UpdateFeature)(const NVSDK_NGX_Application_Identifier*, const NVSDK_NGX_Feature);

// DX11
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_Init)(unsigned long long, const wchar_t*, ID3D11Device*, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_Init_Ext)(unsigned long long, const wchar_t*, ID3D11Device*, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version, unsigned long long);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_Init_ProjectID)(const char*, NVSDK_NGX_EngineType, const char*, const wchar_t*, ID3D11Device*, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_Shutdown)(void);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_Shutdown1)(ID3D11Device*);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_GetScratchBufferSize)(NVSDK_NGX_Feature, const NVSDK_NGX_Parameter*, size_t*);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_GetCapabilityParameters)(NVSDK_NGX_Parameter**);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_GetParameters)(NVSDK_NGX_Parameter**);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_AllocateParameters)(NVSDK_NGX_Parameter**);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_DestroyParameters)(NVSDK_NGX_Parameter*);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_CreateFeature)(ID3D11DeviceContext*, NVSDK_NGX_Feature, NVSDK_NGX_Parameter*, NVSDK_NGX_Handle**);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_ReleaseFeature)(NVSDK_NGX_Handle*);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_EvaluateFeature)(ID3D11DeviceContext*, const NVSDK_NGX_Handle*, const NVSDK_NGX_Parameter*, PFN_NVSDK_NGX_ProgressCallback);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_EvaluateFeature_C)(ID3D11DeviceContext*, const NVSDK_NGX_Handle*, const NVSDK_NGX_Parameter*, PFN_NVSDK_NGX_ProgressCallback_C);

// DX12
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_Init)(unsigned long long, const wchar_t*, ID3D12Device*, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_Init_Ext)(unsigned long long, const wchar_t*, ID3D12Device*, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version, unsigned long long);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_Init_ProjectID)(const char*, NVSDK_NGX_EngineType, const char*, const wchar_t*, ID3D12Device*, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_Init_with_ProjectID)(const char* InProjectId,NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_Shutdown)(void);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_Shutdown1)(ID3D12Device*);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_GetCapabilityParameters)(NVSDK_NGX_Parameter**);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_GetParameters)(NVSDK_NGX_Parameter**);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_AllocateParameters)(NVSDK_NGX_Parameter**);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_DestroyParameters)(NVSDK_NGX_Parameter*);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_GetScratchBufferSize)(NVSDK_NGX_Feature, const NVSDK_NGX_Parameter*, size_t*);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_CreateFeature)(ID3D12GraphicsCommandList*, NVSDK_NGX_Feature, NVSDK_NGX_Parameter*, NVSDK_NGX_Handle**);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_ReleaseFeature)(NVSDK_NGX_Handle*);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_GetFeatureRequirements)(IDXGIAdapter*, const NVSDK_NGX_FeatureDiscoveryInfo*, NVSDK_NGX_FeatureRequirement*);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_EvaluateFeature)(ID3D12GraphicsCommandList*, const NVSDK_NGX_Handle*, const NVSDK_NGX_Parameter*, PFN_NVSDK_NGX_ProgressCallback);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D12_EvaluateFeature_C)(ID3D12GraphicsCommandList*, const NVSDK_NGX_Handle*, const NVSDK_NGX_Parameter*, PFN_NVSDK_NGX_ProgressCallback_C);

// Vulkan
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_RequiredExtensions)(unsigned int*, const char***, unsigned int*, const char***);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_Init)(unsigned long long, const wchar_t*, VkInstance, VkPhysicalDevice, VkDevice, PFN_vkGetInstanceProcAddr, PFN_vkGetDeviceProcAddr, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_Init_Ext)(unsigned long long, const wchar_t*, VkInstance, VkPhysicalDevice, VkDevice, PFN_vkGetInstanceProcAddr, PFN_vkGetDeviceProcAddr, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version, unsigned long long);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_Init_Ext2)(unsigned long long, const wchar_t*, VkInstance, VkPhysicalDevice, VkDevice, PFN_vkGetInstanceProcAddr, PFN_vkGetDeviceProcAddr, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version, unsigned long long, unsigned long long);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_Init_ProjectID)(const char*, NVSDK_NGX_EngineType, const char*, const wchar_t*, VkInstance, VkPhysicalDevice, VkDevice, PFN_vkGetInstanceProcAddr, PFN_vkGetDeviceProcAddr, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_Shutdown)(void);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_Shutdown1)(VkDevice);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_GetCapabilityParameters)(NVSDK_NGX_Parameter**);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_GetParameters)(NVSDK_NGX_Parameter**);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_AllocateParameters)(NVSDK_NGX_Parameter**);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_DestroyParameters)(NVSDK_NGX_Parameter*);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_GetScratchBufferSize)(NVSDK_NGX_Feature, const NVSDK_NGX_Parameter*, size_t*);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_CreateFeature)(VkCommandBuffer, NVSDK_NGX_Feature, NVSDK_NGX_Parameter*, NVSDK_NGX_Handle**);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_CreateFeature1)(VkDevice, VkCommandBuffer, NVSDK_NGX_Feature, NVSDK_NGX_Parameter*, NVSDK_NGX_Handle**);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_ReleaseFeature)(NVSDK_NGX_Handle*);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_GetFeatureRequirements)(const VkInstance, const VkPhysicalDevice, const NVSDK_NGX_FeatureDiscoveryInfo*, NVSDK_NGX_FeatureRequirement*);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_GetFeatureInstanceExtensionRequirements)(const NVSDK_NGX_FeatureDiscoveryInfo, uint32_t*, VkExtensionProperties**);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_GetFeatureDeviceExtensionRequirements)(VkInstance, VkPhysicalDevice, const NVSDK_NGX_FeatureDiscoveryInfo*, uint32_t*, VkExtensionProperties**);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_EvaluateFeature)(VkCommandBuffer, const NVSDK_NGX_Handle*, const NVSDK_NGX_Parameter*, PFN_NVSDK_NGX_ProgressCallback);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_VULKAN_EvaluateFeature_C)(VkCommandBuffer, const NVSDK_NGX_Handle* , const NVSDK_NGX_Parameter* , PFN_NVSDK_NGX_ProgressCallback_C);


// CUDA
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_CUDA_Init)(unsigned long long, const wchar_t*, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_CUDA_Init_Ext)(unsigned long long, const wchar_t*, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version, unsigned long long);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_CUDA_Init_with_ProjectID)(const char*, NVSDK_NGX_EngineType, const char*, const wchar_t*, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_CUDA_Shutdown)(void);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_CUDA_Shutdown1)(void);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_CUDA_GetCapabilityParameters)(NVSDK_NGX_Parameter**);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_CUDA_AllocateParameters)(NVSDK_NGX_Parameter**);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_CUDA_GetCapabilityParameters)(NVSDK_NGX_Parameter**);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_CUDA_DestroyParameters)(NVSDK_NGX_Parameter*);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_CUDA_GetScratchBufferSize)(NVSDK_NGX_Feature, const NVSDK_NGX_Parameter*, size_t*);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_CUDA_CreateFeature)(NVSDK_NGX_Feature, const NVSDK_NGX_Parameter*, NVSDK_NGX_Handle**);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_CUDA_ReleaseFeature)(NVSDK_NGX_Handle*);

typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_CUDA_EvaluateFeature)(const NVSDK_NGX_Handle*, const NVSDK_NGX_Parameter*, PFN_NVSDK_NGX_ProgressCallback);
typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_CUDA_EvaluateFeature_C)(const NVSDK_NGX_Handle*, const NVSDK_NGX_Parameter*, PFN_NVSDK_NGX_ProgressCallback_C);

#endif