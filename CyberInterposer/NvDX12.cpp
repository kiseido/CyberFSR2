#include "pch.h"
#include "NvCommon.h"
#include "Interposer.h"
#include "Logging.h"

using namespace CyberInterposer;

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D12_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath,
    ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion,
    unsigned long long unknown0)
{
    CyberLOG();

    if (function_table.PFN_DX12.pfn_D3D12_Init_Ext != nullptr)
        return function_table.PFN_DX12.pfn_D3D12_Init_Ext(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, unknown0);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
    CyberLOG();

    if (function_table.PFN_DX12.pfn_D3D12_Init != nullptr)
        return function_table.PFN_DX12.pfn_D3D12_Init(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D12_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
    CyberLOG();

    if (function_table.PFN_DX12.pfn_D3D12_Init_ProjectID != nullptr)
        return function_table.PFN_DX12.pfn_D3D12_Init_ProjectID(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Shutdown(void)
{
    CyberLOG();

    if (function_table.PFN_DX12.pfn_D3D12_Shutdown != nullptr)
        return function_table.PFN_DX12.pfn_D3D12_Shutdown();

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Shutdown1(ID3D12Device* InDevice)
{
    CyberLOG();

    if (function_table.PFN_DX12.pfn_D3D12_Shutdown1 != nullptr)
        return function_table.PFN_DX12.pfn_D3D12_Shutdown1(InDevice);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetParameters(NVSDK_NGX_Parameter** OutParameters)
{
    CyberLOG();

    if (function_table.PFN_DX12.pfn_D3D12_GetParameters != nullptr)
        return function_table.PFN_DX12.pfn_D3D12_GetParameters(OutParameters);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters)
{
    CyberLOG();

    if (function_table.PFN_DX12.pfn_D3D12_GetCapabilityParameters != nullptr)
        return function_table.PFN_DX12.pfn_D3D12_GetCapabilityParameters(OutParameters);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_AllocateParameters(NVSDK_NGX_Parameter** OutParameters)
{
    CyberLOG();

    if (function_table.PFN_DX12.pfn_D3D12_AllocateParameters != nullptr)
        return function_table.PFN_DX12.pfn_D3D12_AllocateParameters(OutParameters);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_DestroyParameters(NVSDK_NGX_Parameter* InParameters)
{
    CyberLOG();

    if (function_table.PFN_DX12.pfn_D3D12_DestroyParameters != nullptr)
        return function_table.PFN_DX12.pfn_D3D12_DestroyParameters(InParameters);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId,
    const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes)
{
    CyberLOG();

    if (function_table.PFN_DX12.pfn_D3D12_GetScratchBufferSize != nullptr)
        return function_table.PFN_DX12.pfn_D3D12_GetScratchBufferSize(InFeatureId, InParameters, OutSizeInBytes);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_CreateFeature(ID3D12GraphicsCommandList* InCmdList, NVSDK_NGX_Feature InFeatureID,
    NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
    CyberLOG();

    if (function_table.PFN_DX12.pfn_D3D12_CreateFeature != nullptr)
        return function_table.PFN_DX12.pfn_D3D12_CreateFeature(InCmdList, InFeatureID, InParameters, OutHandle);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_ReleaseFeature(NVSDK_NGX_Handle* InHandle)
{
    CyberLOG();

    if (function_table.PFN_DX12.pfn_D3D12_ReleaseFeature != nullptr)
        return function_table.PFN_DX12.pfn_D3D12_ReleaseFeature(InHandle);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetFeatureRequirements(IDXGIAdapter* Adapter, const NVSDK_NGX_FeatureDiscoveryInfo* FeatureDiscoveryInfo, NVSDK_NGX_FeatureRequirement* OutSupported)
{
    CyberLOG();

    if (function_table.PFN_DX12.pfn_D3D12_GetFeatureRequirements != nullptr)
        return function_table.PFN_DX12.pfn_D3D12_GetFeatureRequirements(Adapter, FeatureDiscoveryInfo, OutSupported);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_EvaluateFeature(ID3D12GraphicsCommandList* InCmdList, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
    CyberLOG();

    if (function_table.PFN_DX12.pfn_D3D12_EvaluateFeature != nullptr)
        return function_table.PFN_DX12.pfn_D3D12_EvaluateFeature(InCmdList, InFeatureHandle, InParameters, InCallback);

    return NVSDK_NGX_Result_Fail;
}