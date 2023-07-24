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

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_Init(unsigned long long a, const wchar_t* b, const NVSDK_NGX_FeatureCommonInfo* c, NVSDK_NGX_Version d);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_Init_Ext(unsigned long long a, const wchar_t* b, const NVSDK_NGX_FeatureCommonInfo* c, NVSDK_NGX_Version d, unsigned long long e);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_Init_with_ProjectID(const char* a, NVSDK_NGX_EngineType b, const char* c, const wchar_t* d, const NVSDK_NGX_FeatureCommonInfo* e, NVSDK_NGX_Version f);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_Shutdown(void);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_Shutdown1(void);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_GetCapabilityParameters(NVSDK_NGX_Parameter** a);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_AllocateParameters(NVSDK_NGX_Parameter** a);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_DestroyParameters(NVSDK_NGX_Parameter* a);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_GetScratchBufferSize(NVSDK_NGX_Feature a, const NVSDK_NGX_Parameter* b, size_t* c);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_CreateFeature(NVSDK_NGX_Feature a, const NVSDK_NGX_Parameter* b, NVSDK_NGX_Handle** c);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_ReleaseFeature(NVSDK_NGX_Handle* a);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_EvaluateFeature(const NVSDK_NGX_Handle* a, const NVSDK_NGX_Parameter* b, PFN_NVSDK_NGX_ProgressCallback c);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_EvaluateFeature_C(const NVSDK_NGX_Handle* a, const NVSDK_NGX_Parameter* b, PFN_NVSDK_NGX_ProgressCallback_C c);

#endif