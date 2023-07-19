#include "pch.h"
#include "NGX_Interposer.h"


bool CyberInterposer::PFN_Table_NVNGX_Top_Interposer::LoadDLL(HMODULE hModule, bool populateChildren)
{
    CyberLogArgs(hModule, populateChildren);

    if (hModule == nullptr || hModule == 0) {
        CyberLOGy("hModule is bad");
        return false;
    }
    
    const bool foundParameter = PFN_Parameter.LoadDLL(hModule, false);

    if (populateChildren) {
        const bool foundDx11 = PFN_DX11.LoadDLL(hModule, false);
        const bool foundDx12 = PFN_DX12.LoadDLL(hModule, false);
        const bool foundCuda = PFN_CUDA.LoadDLL(hModule, false);
        const bool foundVulkan = PFN_Vulkan.LoadDLL(hModule, false);

        if (foundDx11)
            CyberLOGy("DX11 functions loaded");
        else 
            CyberLOGy("DX11 functions not found");

        if (foundDx12)
            CyberLOGy("DX12 functions loaded");
        else 
            CyberLOGy("DX12 functions not found");

        if (foundDx12)
            CyberLOGy("CUDA functions loaded");
        else 
            CyberLOGy("CUDA functions not found");

        if (foundDx12)
            CyberLOGy("Vulkan functions loaded");
        else 
            CyberLOGy("Vulkan functions not found");
    }

    return foundParameter;
}

NVSDK_NGX_Result NVSDK_NGX_UpdateFeature(const NVSDK_NGX_Application_Identifier* ApplicationId, const NVSDK_NGX_Feature FeatureID)
{
    CyberLogArgs(ApplicationId, FeatureID);
	
	return NVSDK_NGX_Result_Fail;
}

inline HMODULE CyberInterposer::PFN_Table_T::GetHModule(LPCWSTR inputFileName)
{
    CyberLogArgs(inputFileName);

    HMODULE hModule = LoadLibraryW(inputFileName);

    return hModule;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_GetVersion(NVSDK_NGX_Version* version)
{
    CyberLogArgs(version);
    return NVSDK_NGX_Result_Fail;
}
