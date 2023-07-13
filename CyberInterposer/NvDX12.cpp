#include "pch.h"
#include "NvCommon.h"
#include "Interposer.h"
#include "Logger.h"

using namespace Interposer;

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D12_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath,
    ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion,
    unsigned long long unknown0)
{
    if (pfn_D3D12_Init_Ext != nullptr)
        return pfn_D3D12_Init_Ext(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, unknown0);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
    if (pfn_D3D12_Init != nullptr)
        return pfn_D3D12_Init(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D12_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
    if (pfn_D3D12_Init_ProjectID != nullptr)
        return pfn_D3D12_Init_ProjectID(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Shutdown(void)
{
    if (pfn_D3D12_Shutdown != nullptr)
        return pfn_D3D12_Shutdown();

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Shutdown1(ID3D12Device* InDevice)
{
    if (pfn_D3D12_Shutdown1 != nullptr)
        return pfn_D3D12_Shutdown1(InDevice);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetParameters(NVSDK_NGX_Parameter** OutParameters)
{
    if (pfn_D3D12_GetParameters != nullptr)
        return pfn_D3D12_GetParameters(OutParameters);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters)
{
    if (pfn_D3D12_GetCapabilityParameters != nullptr)
        return pfn_D3D12_GetCapabilityParameters(OutParameters);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_AllocateParameters(NVSDK_NGX_Parameter** OutParameters)
{
    if (pfn_D3D12_AllocateParameters != nullptr)
        return pfn_D3D12_AllocateParameters(OutParameters);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_DestroyParameters(NVSDK_NGX_Parameter* InParameters)
{
    if (pfn_D3D12_DestroyParameters != nullptr)
        return pfn_D3D12_DestroyParameters(InParameters);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId,
    const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes)
{
    if (pfn_D3D12_GetScratchBufferSize != nullptr)
        return pfn_D3D12_GetScratchBufferSize(InFeatureId, InParameters, OutSizeInBytes);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_CreateFeature(ID3D12GraphicsCommandList* InCmdList, NVSDK_NGX_Feature InFeatureID,
    NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
    if (pfn_D3D12_CreateFeature != nullptr)
        return pfn_D3D12_CreateFeature(InCmdList, InFeatureID, InParameters, OutHandle);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_ReleaseFeature(NVSDK_NGX_Handle* InHandle)
{
    if (pfn_D3D12_ReleaseFeature != nullptr)
        return pfn_D3D12_ReleaseFeature(InHandle);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetFeatureRequirements(IDXGIAdapter* Adapter, const NVSDK_NGX_FeatureDiscoveryInfo* FeatureDiscoveryInfo, NVSDK_NGX_FeatureRequirement* OutSupported)
{
    if (pfn_D3D12_GetFeatureRequirements != nullptr)
        return pfn_D3D12_GetFeatureRequirements(Adapter, FeatureDiscoveryInfo, OutSupported);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_EvaluateFeature(ID3D12GraphicsCommandList* InCmdList, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
    if (pfn_D3D12_EvaluateFeature != nullptr)
        return pfn_D3D12_EvaluateFeature(InCmdList, InFeatureHandle, InParameters, InCallback);

    return NVSDK_NGX_Result_Fail;
}