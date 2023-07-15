#include "pch.h"
#include "Interposer.h"
#include "Logging.h"

bool CyberInterposer::Top_Interposer::LoadDependentDLL(HMODULE hModule)
{
    CyberLOG();
    return LoadDependentDLL(hModule, false);
}

// Function that loads the dependent DLL and retrieves function pointers
bool CyberInterposer::Top_Interposer::LoadDependentDLL(LPCWSTR inputFileName, bool populateChildren)
{
    CyberLOGy(CyberLogger::LPCWSTRToString(inputFileName));

    HMODULE hModule = LoadLibraryW(inputFileName);

    return LoadDependentDLL(hModule, populateChildren);
}

bool CyberInterposer::Top_Interposer::LoadDependentDLL(HMODULE hModule, bool populateChildren)
{
    CyberLOG();

    if (hModule == nullptr)
    {
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

    if (!populateChildren) return true;

    PFN_DX11.LoadDependentDLL(hModule);
    PFN_DX12.LoadDependentDLL(hModule);
    PFN_CUDA.LoadDependentDLL(hModule);
    PFN_Vulkan.LoadDependentDLL(hModule);

    // Vulkan

    return true;
}



NVSDK_NGX_Result NVSDK_NGX_UpdateFeature(const NVSDK_NGX_Application_Identifier* ApplicationId, const NVSDK_NGX_Feature FeatureID)
{
	CyberLOG();

	
	return NVSDK_NGX_Result_Fail;
}

inline HMODULE CyberInterposer::PFN_Table_T::GetHModule(LPCWSTR inputFileName)
{
    CyberLOGy(CyberLogger::LPCWSTRToString(inputFileName));

    HMODULE hModule = LoadLibraryW(inputFileName);

    return hModule;
}

bool CyberInterposer::PFN_Table_DX11::LoadDependentDLL(HMODULE hModule)
{
    CyberLOG();

    if (hModule == nullptr) 
    {
        return false;
    }

    pfn_SetD3d11Resource = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetD3d11Resource>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_SetD3d12Resource"));
    pfn_GetD3d11Resource = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetD3d11Resource>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_GetD3d12Resource"));

    pfn_D3D11_Init = reinterpret_cast<PFN_NVSDK_NGX_D3D11_Init>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_Init"));
    pfn_D3D11_Init_Ext = reinterpret_cast<PFN_NVSDK_NGX_D3D11_Init_Ext>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_Init_Ext"));
    pfn_D3D11_Init_ProjectID = reinterpret_cast<PFN_NVSDK_NGX_D3D11_Init_ProjectID>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_Init_ProjectID"));

    pfn_D3D11_Shutdown = reinterpret_cast<PFN_NVSDK_NGX_D3D11_Shutdown>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_Shutdown"));
    pfn_D3D11_Shutdown1 = reinterpret_cast<PFN_NVSDK_NGX_D3D11_Shutdown1>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_Shutdown1"));

    pfn_D3D11_GetCapabilityParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D11_GetCapabilityParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_GetCapabilityParameters"));
    pfn_D3D11_GetParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D11_GetParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_GetParameters"));

    pfn_D3D11_GetScratchBufferSize = reinterpret_cast<PFN_NVSDK_NGX_D3D11_GetScratchBufferSize>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_GetScratchBufferSize"));

    pfn_D3D11_CreateFeature = reinterpret_cast<PFN_NVSDK_NGX_D3D11_CreateFeature>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_CreateFeature"));
    pfn_D3D11_ReleaseFeature = reinterpret_cast<PFN_NVSDK_NGX_D3D11_ReleaseFeature>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_ReleaseFeature"));
    pfn_D3D11_EvaluateFeature = reinterpret_cast<PFN_NVSDK_NGX_D3D11_EvaluateFeature>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_EvaluateFeature"));
    pfn_D3D11_EvaluateFeature_C = reinterpret_cast<PFN_NVSDK_NGX_D3D11_EvaluateFeature_C>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_EvaluateFeature_C"));

    pfn_D3D11_AllocateParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D11_AllocateParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_AllocateParameters"));
    pfn_D3D11_DestroyParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D11_DestroyParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_DestroyParameters"));

    return true;
}

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

bool CyberInterposer::PFN_Table_CUDA::LoadDependentDLL(HMODULE hModule)
{
    CyberLOG();

    if (hModule == nullptr) 
    {
        return false;
    }

    pfn_cuInit = reinterpret_cast<PFN_NVSDK_NGX_CUDA_Init>(GetProcAddress(hModule, "cuInit"));
    pfn_cuInit_Ext = reinterpret_cast<PFN_NVSDK_NGX_CUDA_Init_Ext>(GetProcAddress(hModule, "cuInit_Ext"));
    pfn_cuInit_with_ProjectID = reinterpret_cast<PFN_NVSDK_NGX_CUDA_Init_with_ProjectID>(GetProcAddress(hModule, "cuInit_with_ProjectID"));

    pfn_cuShutdown = reinterpret_cast<PFN_NVSDK_NGX_CUDA_Shutdown>(GetProcAddress(hModule, "cuShutdown"));

    pfn_cuGetCapabilityParameters = reinterpret_cast<PFN_NVSDK_NGX_CUDA_GetCapabilityParameters>(GetProcAddress(hModule, "cuGetCapabilityParameters"));

    pfn_cuAllocateParameters = reinterpret_cast<PFN_NVSDK_NGX_CUDA_AllocateParameters>(GetProcAddress(hModule, "cuAllocateParameters"));
    pfn_cuDestroyParameters = reinterpret_cast<PFN_NVSDK_NGX_CUDA_DestroyParameters>(GetProcAddress(hModule, "cuDestroyParameters"));

    pfn_cuGetScratchBufferSize = reinterpret_cast<PFN_NVSDK_NGX_CUDA_GetScratchBufferSize>(GetProcAddress(hModule, "cuGetScratchBufferSize"));

    pfn_cuCreateFeature = reinterpret_cast<PFN_NVSDK_NGX_CUDA_CreateFeature>(GetProcAddress(hModule, "cuCreateFeature"));
    pfn_cuReleaseFeature = reinterpret_cast<PFN_NVSDK_NGX_CUDA_ReleaseFeature>(GetProcAddress(hModule, "cuReleaseFeature"));
    pfn_cuEvaluateFeature = reinterpret_cast<PFN_NVSDK_NGX_CUDA_EvaluateFeature>(GetProcAddress(hModule, "cuEvaluateFeature"));
    pfn_cuEvaluateFeature_C = reinterpret_cast<PFN_NVSDK_NGX_CUDA_EvaluateFeature_C>(GetProcAddress(hModule, "cuEvaluateFeature_C"));

    return true;
}

bool CyberInterposer::PFN_Table_Vulkan::LoadDependentDLL(HMODULE hModule)
{
    CyberLOG();

    if (hModule == nullptr) {
        return false;
    }
    pfn_VULKAN_Init = reinterpret_cast<PFN_NVSDK_NGX_VULKAN_Init>(GetProcAddress(hModule, "NVSDK_NGX_VULKAN_Init"));
    pfn_VULKAN_Init_Ext = reinterpret_cast<PFN_NVSDK_NGX_VULKAN_Init_Ext>(GetProcAddress(hModule, "NVSDK_NGX_VULKAN_Init_Ext"));
    pfn_VULKAN_Init_ProjectID = reinterpret_cast<PFN_NVSDK_NGX_VULKAN_Init_ProjectID>(GetProcAddress(hModule, "NVSDK_NGX_VULKAN_Init_ProjectID"));

    pfn_VULKAN_Shutdown = reinterpret_cast<PFN_NVSDK_NGX_VULKAN_Shutdown>(GetProcAddress(hModule, "NVSDK_NGX_VULKAN_Shutdown"));
    pfn_VULKAN_Shutdown1 = reinterpret_cast<PFN_NVSDK_NGX_VULKAN_Shutdown1>(GetProcAddress(hModule, "NVSDK_NGX_VULKAN_Shutdown1"));

    pfn_VULKAN_GetCapabilityParameters = reinterpret_cast<PFN_NVSDK_NGX_VULKAN_GetCapabilityParameters>(GetProcAddress(hModule, "NVSDK_NGX_VULKAN_GetCapabilityParameters"));
    pfn_VULKAN_GetParameters = reinterpret_cast<PFN_NVSDK_NGX_VULKAN_GetParameters>(GetProcAddress(hModule, "NVSDK_NGX_VULKAN_GetParameters"));

    pfn_VULKAN_AllocateParameters = reinterpret_cast<PFN_NVSDK_NGX_VULKAN_AllocateParameters>(GetProcAddress(hModule, "NVSDK_NGX_VULKAN_AllocateParameters"));
    pfn_VULKAN_DestroyParameters = reinterpret_cast<PFN_NVSDK_NGX_VULKAN_DestroyParameters>(GetProcAddress(hModule, "NVSDK_NGX_VULKAN_DestroyParameters"));

    pfn_VULKAN_GetScratchBufferSize = reinterpret_cast<PFN_NVSDK_NGX_VULKAN_GetScratchBufferSize>(GetProcAddress(hModule, "NVSDK_NGX_VULKAN_GetScratchBufferSize"));

    pfn_VULKAN_CreateFeature = reinterpret_cast<PFN_NVSDK_NGX_VULKAN_CreateFeature>(GetProcAddress(hModule, "NVSDK_NGX_VULKAN_CreateFeature"));
    pfn_VULKAN_ReleaseFeature = reinterpret_cast<PFN_NVSDK_NGX_VULKAN_ReleaseFeature>(GetProcAddress(hModule, "NVSDK_NGX_VULKAN_ReleaseFeature"));
    pfn_VULKAN_EvaluateFeature = reinterpret_cast<PFN_NVSDK_NGX_VULKAN_EvaluateFeature>(GetProcAddress(hModule, "NVSDK_NGX_VULKAN_EvaluateFeature"));
    pfn_VULKAN_EvaluateFeature_C = reinterpret_cast<PFN_NVSDK_NGX_VULKAN_EvaluateFeature_C>(GetProcAddress(hModule, "NVSDK_NGX_VULKAN_EvaluateFeature_C"));

    return true;
}

