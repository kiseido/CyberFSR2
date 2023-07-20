#include "pch.h"

#ifndef CyInt_NVCUDA
#define CyInt_NVCUDA

#include "Common.h"

namespace CyberInterposer
{
    struct PFN_Table_NVNGX_CUDA : public  PFN_Table_T
    {
        PFN_NVSDK_NGX_CUDA_Init pfn_cuInit = nullptr;
        PFN_NVSDK_NGX_CUDA_Init_Ext pfn_cuInit_Ext = nullptr;
        PFN_NVSDK_NGX_CUDA_Init_with_ProjectID pfn_cuInit_with_ProjectID = nullptr;

        PFN_NVSDK_NGX_CUDA_Shutdown pfn_cuShutdown = nullptr;
        PFN_NVSDK_NGX_CUDA_Shutdown1 pfn_cuShutdown1 = nullptr;

        PFN_NVSDK_NGX_CUDA_GetCapabilityParameters pfn_cuGetCapabilityParameters = nullptr;

        PFN_NVSDK_NGX_CUDA_AllocateParameters pfn_cuAllocateParameters = nullptr;
        PFN_NVSDK_NGX_CUDA_DestroyParameters pfn_cuDestroyParameters = nullptr;

        PFN_NVSDK_NGX_CUDA_GetScratchBufferSize pfn_cuGetScratchBufferSize = nullptr;

        PFN_NVSDK_NGX_CUDA_CreateFeature pfn_cuCreateFeature = nullptr;
        PFN_NVSDK_NGX_CUDA_ReleaseFeature pfn_cuReleaseFeature = nullptr;
        PFN_NVSDK_NGX_CUDA_EvaluateFeature pfn_cuEvaluateFeature = nullptr;
        PFN_NVSDK_NGX_CUDA_EvaluateFeature_C pfn_cuEvaluateFeature_C = nullptr;

        bool LoadDLL(HMODULE inputFile, bool populateChildren) override;
    };
}
#endif