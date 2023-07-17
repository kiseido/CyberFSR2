#include "pch.h"
#include "Interposer.h"
#include "Logging.h"

bool CyberInterposer::Top_Interposer::LoadDependentDLL(HMODULE hModule)
{
    CyberLogArgs(hModule);
    return LoadDependentDLL(hModule, false);
}

// Function that loads the dependent DLL and retrieves function pointers
bool CyberInterposer::Top_Interposer::LoadDependentDLL(LPCWSTR inputFileName, bool populateChildren)
{
    CyberLogArgs(inputFileName, populateChildren);
    //CyberLOGy(CyberLogger::LPCWSTRToString(inputFileName));

    HMODULE hModule = LoadLibraryW(inputFileName);

    return LoadDependentDLL(hModule, populateChildren);
}

bool CyberInterposer::Top_Interposer::LoadDependentDLL(HMODULE hModule, bool populateChildren)
{
    CyberLogArgs(hModule, populateChildren);

    if (hModule == nullptr || hModule == 0) {
        CyberLOGy("hModule is bad");
        return false;
    }

    // common
    pfn_GetULL = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetULL>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_GetULL"));
    pfn_SetULL = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetULL>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_SetULL"));
    pfn_GetD = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetD>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_GetD"));
    pfn_SetD = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetD>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_SetD"));
    pfn_GetI = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetI>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_GetI"));
    pfn_SetI = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetI>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_SetI"));
    pfn_SetVoidPointer = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetVoidPointer>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_SetVoidPointer"));
    pfn_GetVoidPointer = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetVoidPointer>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_GetVoidPointer"));
    pfn_GetF = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetF>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_GetF"));
    pfn_SetF = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetF>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_SetF"));
    pfn_GetUI = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetUI>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_GetUI"));
    pfn_SetUI = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetUI>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_SetUI"));

    const bool foundCommonFunctions =
        (pfn_GetULL != nullptr) &&
        (pfn_SetULL != nullptr) &&
        (pfn_GetD != nullptr) &&
        (pfn_SetD != nullptr) &&
        (pfn_GetI != nullptr) &&
        (pfn_SetI != nullptr) &&
        (pfn_SetVoidPointer != nullptr) &&
        (pfn_GetVoidPointer != nullptr) &&
        (pfn_GetF != nullptr) &&
        (pfn_SetF != nullptr) &&
        (pfn_GetUI != nullptr) &&
        (pfn_SetUI != nullptr);

    if (foundCommonFunctions == false) {
        CyberLOGy("NVNGX common functions not found");
        return false;
    }

    if (populateChildren) {
        const bool foundDx11 = PFN_DX11.LoadDependentDLL(hModule);
        const bool foundDx12 = PFN_DX12.LoadDependentDLL(hModule);
        const bool foundCuda = PFN_CUDA.LoadDependentDLL(hModule);
        const bool foundVulkan = PFN_Vulkan.LoadDependentDLL(hModule);

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

    return true;
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
