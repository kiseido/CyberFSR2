#include "pch.h"
#include "NGX_Interposer.h"

#ifdef CyberInterposer_DO_DX12

namespace CyberInterposer {
    bool PFN_Table_NVNGX_DX12::LoadDLL(HMODULE hModule, bool populateChildren)
    {
        CyberLogArgs(hModule, populateChildren);

        if (hModule == nullptr)
        {
            return false;
        }

        bool foundFunctions = true;

        foundFunctions &= LoadFunction(pfn_D3D12_Init, hModule, "NVSDK_NGX_D3D12_Init");
        foundFunctions &= LoadFunction(pfn_D3D12_Init_Ext, hModule, "NVSDK_NGX_D3D12_Init_Ext");
        foundFunctions &= LoadFunction(pfn_D3D12_Init_ProjectID, hModule, "NVSDK_NGX_D3D12_Init_ProjectID");
        foundFunctions &= LoadFunction(pfn_D3D12_Init_with_ProjectID, hModule, "NVSDK_NGX_D3D12_Init_with_ProjectID");
        foundFunctions &= LoadFunction(pfn_D3D12_Shutdown, hModule, "NVSDK_NGX_D3D12_Shutdown");
        foundFunctions &= LoadFunction(pfn_D3D12_Shutdown1, hModule, "NVSDK_NGX_D3D12_Shutdown1");
        foundFunctions &= LoadFunction(pfn_D3D12_GetCapabilityParameters, hModule, "NVSDK_NGX_D3D12_GetCapabilityParameters");
        foundFunctions &= LoadFunction(pfn_D3D12_GetParameters, hModule, "NVSDK_NGX_D3D12_GetParameters");
        foundFunctions &= LoadFunction(pfn_D3D12_GetScratchBufferSize, hModule, "NVSDK_NGX_D3D12_GetScratchBufferSize");
        foundFunctions &= LoadFunction(pfn_D3D12_CreateFeature, hModule, "NVSDK_NGX_D3D12_CreateFeature");
        foundFunctions &= LoadFunction(pfn_D3D12_ReleaseFeature, hModule, "NVSDK_NGX_D3D12_ReleaseFeature");
        foundFunctions &= LoadFunction(pfn_D3D12_GetFeatureRequirements, hModule, "NVSDK_NGX_D3D12_GetFeatureRequirements");
        foundFunctions &= LoadFunction(pfn_D3D12_EvaluateFeature, hModule, "NVSDK_NGX_D3D12_EvaluateFeature");
        foundFunctions &= LoadFunction(pfn_D3D12_EvaluateFeature_C, hModule, "NVSDK_NGX_D3D12_EvaluateFeature_C");
        foundFunctions &= LoadFunction(pfn_D3D12_AllocateParameters, hModule, "NVSDK_NGX_D3D12_AllocateParameters");
        foundFunctions &= LoadFunction(pfn_D3D12_DestroyParameters, hModule, "NVSDK_NGX_D3D12_DestroyParameters");

        return foundFunctions;
    }
}



NVSDK_NGX_Result NVSDK_NGX_D3D12_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath,
    ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion,
    unsigned long long unknown0)
{
    const CyberTypes::RTC start = CyberTypes::RTC(true);
    CyberInterposer::interposer.wait_for_ready();
    CyberLogArgs(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, unknown0, start);

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_Init_Ext;

    if (ptr != nullptr)
    {
        auto result = ptr(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, unknown0);
        CyberLOGvi(result);
        return result;
    }

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
    const CyberTypes::RTC start = CyberTypes::RTC(true);
    CyberInterposer::interposer.wait_for_ready();
    CyberLogArgs(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, start);

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_Init;

    if (ptr != nullptr)
    {
        auto result = ptr(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);
        CyberLOGvi(result);
        return result;
    }

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
    const CyberTypes::RTC start = CyberTypes::RTC(true);
    CyberInterposer::interposer.wait_for_ready();
    CyberLogArgs(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, start);

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_Init_ProjectID;

    if (ptr != nullptr)
    {
        auto result = ptr(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);
        CyberLOGvi(result);
        return result;
    }

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Init_with_ProjectID(
    const char* InProjectId,
    NVSDK_NGX_EngineType InEngineType,
    const char* InEngineVersion,
    const wchar_t* InApplicationDataPath,
    ID3D12Device* InDevice,
    const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo,
    NVSDK_NGX_Version InSDKVersion)
{
    const CyberTypes::RTC start = CyberTypes::RTC(true);
    CyberInterposer::interposer.wait_for_ready();
    CyberLogArgs(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, start);

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_Init_ProjectID;

    if (ptr != nullptr)
    {
        auto result = ptr(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);
        CyberLOGvi(result);
        return result;
    }

    return NVSDK_NGX_Result_Fail;
}


NVSDK_NGX_Result NVSDK_NGX_D3D12_Shutdown(void)
{
    const CyberTypes::RTC start = CyberTypes::RTC(true);
    CyberInterposer::interposer.wait_for_ready();
    CyberLogArgs(start);

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_Shutdown;

    if (ptr != nullptr)
    {
        auto result = ptr();
        CyberLOGvi(result);
        return result;
    }

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Shutdown1(ID3D12Device* InDevice)
{
    const CyberTypes::RTC start = CyberTypes::RTC(true);
    CyberInterposer::interposer.wait_for_ready();
    CyberLogArgs(InDevice, start);

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_Shutdown1;

    if (ptr != nullptr)
    {
        auto result = ptr(InDevice);
        CyberLOGvi(result);
        return result;
    }

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetParameters(NVSDK_NGX_Parameter** OutParameters)
{
    const CyberTypes::RTC start = CyberTypes::RTC(true);
    CyberInterposer::interposer.wait_for_ready();
    CyberLogArgs(OutParameters, start);

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_GetParameters;

    if (ptr != nullptr)
    {
        auto result = ptr(OutParameters);
        CyberLOGvi(result);
        return result;
    }

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters)
{
    const CyberTypes::RTC start = CyberTypes::RTC(true);
    CyberInterposer::interposer.wait_for_ready();
    CyberLogArgs(OutParameters, start);

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_GetCapabilityParameters;

    if (ptr != nullptr)
    {
        auto result = ptr(OutParameters);
        CyberLOGvi(result);
        return result;
    }

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_AllocateParameters(NVSDK_NGX_Parameter** OutParameters)
{
    const CyberTypes::RTC start = CyberTypes::RTC(true);
    CyberInterposer::interposer.wait_for_ready();
    CyberLogArgs(OutParameters, start);

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_AllocateParameters;

    if (ptr != nullptr)
    {
        auto result = ptr(OutParameters);
        CyberLOGvi(result);
        return result;
    }

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_DestroyParameters(NVSDK_NGX_Parameter* InParameters)
{
    const CyberTypes::RTC start = CyberTypes::RTC(true);
    CyberInterposer::interposer.wait_for_ready();
    CyberLogArgs(InParameters, start);

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_DestroyParameters;

    if (ptr != nullptr)
    {
        auto result = ptr(InParameters);
        CyberLOGvi(result);
        return result;
    }

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId,
    const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes)
{
    const CyberTypes::RTC start = CyberTypes::RTC(true);
    CyberInterposer::interposer.wait_for_ready();
    CyberLogArgs(InFeatureId, InParameters, OutSizeInBytes, start);

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_GetScratchBufferSize;

    if (ptr != nullptr)
    {
        auto result = ptr(InFeatureId, InParameters, OutSizeInBytes);
        CyberLOGvi(result);
        return result;
    }

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_CreateFeature(ID3D12GraphicsCommandList* InCmdList, NVSDK_NGX_Feature InFeatureID,
    NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
    const CyberTypes::RTC start = CyberTypes::RTC(true);
    CyberInterposer::interposer.wait_for_ready();
    CyberLogArgs(InCmdList, InFeatureID, InParameters, OutHandle, start);

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_CreateFeature;

    if (ptr != nullptr)
    {
        auto result = ptr(InCmdList, InFeatureID, InParameters, OutHandle);
        CyberLOGvi(result);
        return result;
    }

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_ReleaseFeature(NVSDK_NGX_Handle* InHandle)
{
    const CyberTypes::RTC start = CyberTypes::RTC(true);
    CyberInterposer::interposer.wait_for_ready();
    CyberLogArgs(InHandle, start);

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_ReleaseFeature;

    if (ptr != nullptr)
    {
        auto result = ptr(InHandle);
        CyberLOGvi(result);
        return result;
    }

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetFeatureRequirements(IDXGIAdapter* Adapter, const NVSDK_NGX_FeatureDiscoveryInfo* FeatureDiscoveryInfo, NVSDK_NGX_FeatureRequirement* OutSupported)
{
    const CyberTypes::RTC start = CyberTypes::RTC(true);
    CyberInterposer::interposer.wait_for_ready();
    CyberLogArgs(Adapter, FeatureDiscoveryInfo, OutSupported, start);

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_GetFeatureRequirements;

    if (ptr != nullptr)
    {
        auto result = ptr(Adapter, FeatureDiscoveryInfo, OutSupported);
        CyberLOGvi(result);
        return result;
    }

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_EvaluateFeature(ID3D12GraphicsCommandList* InCmdList, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
    const CyberTypes::RTC start = CyberTypes::RTC(true);
    CyberInterposer::interposer.wait_for_ready();
    CyberLogArgs(InCmdList, InFeatureHandle, InParameters, InCallback, start);

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_EvaluateFeature;

    if (ptr != nullptr)
    {
        auto result = ptr(InCmdList, InFeatureHandle, InParameters, InCallback);
        CyberLOGvi(result);
        return result;
    }

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D12_EvaluateFeature_C(ID3D12GraphicsCommandList* InCmdList, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback_C InCallback)
{
    const CyberTypes::RTC start = CyberTypes::RTC(true);
    CyberInterposer::interposer.wait_for_ready();
    CyberLogArgs(InCmdList, InFeatureHandle, InParameters, InCallback, start);

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX12.pfn_D3D12_EvaluateFeature_C;

    if (ptr != nullptr)
    {
        auto result = ptr(InCmdList, InFeatureHandle, InParameters, InCallback);
        CyberLOGvi(result);
        return result;
    }

    return NVSDK_NGX_Result_Fail;
}

#endif