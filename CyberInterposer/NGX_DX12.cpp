#include "pch.h"
#include "NGX_Interposer.h"

using namespace CyberInterposer;

bool CyberInterposer::PFN_Table_NVNGX_DX12::LoadDLL(HMODULE hModule, bool populateChildren)
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

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_Init_Ext;

    if (ptr != nullptr)
        return ptr(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, unknown0);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_Init;

    if (ptr != nullptr)
        return ptr(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D12_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_Init_ProjectID;

    if (ptr != nullptr)
        return ptr(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Shutdown(void)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_Shutdown;

    if (ptr != nullptr)
        return ptr();

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Shutdown1(ID3D12Device* InDevice)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_Shutdown1;

    if (ptr != nullptr)
        return ptr(InDevice);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetParameters(NVSDK_NGX_Parameter** OutParameters)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_GetParameters;

    if (ptr != nullptr)
        return ptr(OutParameters);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_GetCapabilityParameters;

    if (ptr != nullptr)
        return ptr(OutParameters);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_AllocateParameters(NVSDK_NGX_Parameter** OutParameters)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_AllocateParameters;

    if (ptr != nullptr)
        return ptr(OutParameters);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_DestroyParameters(NVSDK_NGX_Parameter* InParameters)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_DestroyParameters;

    if (ptr != nullptr)
        return ptr(InParameters);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId,
    const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_GetScratchBufferSize;

    if (ptr != nullptr)
        return ptr(InFeatureId, InParameters, OutSizeInBytes);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_CreateFeature(ID3D12GraphicsCommandList* InCmdList, NVSDK_NGX_Feature InFeatureID,
    NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_CreateFeature;

    if (ptr != nullptr)
        return ptr(InCmdList, InFeatureID, InParameters, OutHandle);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_ReleaseFeature(NVSDK_NGX_Handle* InHandle)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_ReleaseFeature;

    if (ptr != nullptr)
        return ptr(InHandle);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetFeatureRequirements(IDXGIAdapter* Adapter, const NVSDK_NGX_FeatureDiscoveryInfo* FeatureDiscoveryInfo, NVSDK_NGX_FeatureRequirement* OutSupported)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_GetFeatureRequirements;

    if (ptr != nullptr)
        return ptr(Adapter, FeatureDiscoveryInfo, OutSupported);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_EvaluateFeature(ID3D12GraphicsCommandList* InCmdList, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_EvaluateFeature;

    if (ptr != nullptr)
        return ptr(InCmdList, InFeatureHandle, InParameters, InCallback);

    return NVSDK_NGX_Result_Fail;
}