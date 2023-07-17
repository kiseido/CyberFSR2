#include "pch.h"
#include "NvCommon.h"
#include "Interposer.h"
#include "Logging.h"

using namespace CyberInterposer;

bool CyberInterposer::PFN_Table_DX12::LoadDependentDLL(HMODULE hModule)
{
    CyberLOG();

    if (hModule == nullptr)
    {
        return false;
    }

    pfn_SetD3d12Resource = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetD3d12Resource>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_SetD3d12Resource"));
    pfn_GetD3d12Resource = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetD3d12Resource>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_GetD3d12Resource"));

    pfn_D3D12_Init = reinterpret_cast<PFN_NVSDK_NGX_D3D12_Init>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_Init"));
    pfn_D3D12_Init_Ext = reinterpret_cast<PFN_NVSDK_NGX_D3D12_Init_Ext>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_Init_Ext"));
    pfn_D3D12_Init_ProjectID = reinterpret_cast<PFN_NVSDK_NGX_D3D12_Init_ProjectID>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_Init_ProjectID"));

    pfn_D3D12_Shutdown = reinterpret_cast<PFN_NVSDK_NGX_D3D12_Shutdown>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_Shutdown"));
    pfn_D3D12_Shutdown1 = reinterpret_cast<PFN_NVSDK_NGX_D3D12_Shutdown1>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_Shutdown1"));

    pfn_D3D12_GetCapabilityParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D12_GetCapabilityParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_GetCapabilityParameters"));
    pfn_D3D12_GetParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D12_GetParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_GetParameters"));

    pfn_D3D12_AllocateParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D12_AllocateParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_AllocateParameters"));
    pfn_D3D12_DestroyParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D12_DestroyParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_DestroyParameters"));
    pfn_D3D12_GetScratchBufferSize = reinterpret_cast<PFN_NVSDK_NGX_D3D12_GetScratchBufferSize>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_GetScratchBufferSize"));

    pfn_D3D12_CreateFeature = reinterpret_cast<PFN_NVSDK_NGX_D3D12_CreateFeature>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_CreateFeature"));
    pfn_D3D12_ReleaseFeature = reinterpret_cast<PFN_NVSDK_NGX_D3D12_ReleaseFeature>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_ReleaseFeature"));

    pfn_D3D12_GetFeatureRequirements = reinterpret_cast<PFN_NVSDK_NGX_D3D12_GetFeatureRequirements>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_GetFeatureRequirements"));

    pfn_D3D12_EvaluateFeature = reinterpret_cast<PFN_NVSDK_NGX_D3D12_EvaluateFeature>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_EvaluateFeature"));
    pfn_D3D12_EvaluateFeature_C = reinterpret_cast<PFN_NVSDK_NGX_D3D12_EvaluateFeature_C>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_EvaluateFeature_C"));

    return true;
}

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