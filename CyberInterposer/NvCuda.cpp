#include "pch.h"
#include "NvCuda.h"
#include "NvCommon.h"
#include "Interposer.h"
#include "Logging.h"

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