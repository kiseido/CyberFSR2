#include "pch.h"
#include "NGX_Interposer.h"

using namespace CyberInterposer;

bool PFN_Table_NVNGX_Top_Interposer::LoadDLL(HMODULE hModule, bool populateChildren)
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

bool CyberInterposer::DLLRepo::LoadDLL(HMODULE hModule, bool populateChildren)
{
    CyberLogArgs(hModule, populateChildren);

    if (index_in_use == -1) index_in_use = 0;

    return dlls[index_in_use].LoadDLL(hModule, populateChildren);
}

bool CyberInterposer::DLLRepo::UseLoadedDLL(size_t index)
{
    CyberLogArgs(index);
    return false;
}

const std::array<NVNGX_NvDLL, DLLRepo::RepoMaxLoadedDLLs>* CyberInterposer::DLLRepo::GetLoadedDLLs()
{
    CyberLogArgs();

    return &dlls;
}

const NVNGX_NvDLL& CyberInterposer::DLLRepo::GetLoadedDLL()
{
    CyberLogArgs();

    return dlls[0];
}

void CyberInterposer::DLLRepo::ThreadConnect(HMODULE hModule)
{
    CyberLogArgs(hModule);
}

void CyberInterposer::DLLRepo::ThreadDisconnect(HMODULE hModule)
{
    CyberLogArgs(hModule);
}

void CyberInterposer::DLLRepo::ProcessConnect(HMODULE hModule)
{
    CyberLogArgs(hModule);
}

void CyberInterposer::DLLRepo::ProcessDisconnect(HMODULE hModule)
{
    CyberLogArgs(hModule);
}

bool CyberInterposer::NVNGX_NvDLL::LoadDLL(HMODULE inputFile, bool populateChildren)
{
    return pointer_tables.LoadDLL(inputFile, populateChildren);
}
