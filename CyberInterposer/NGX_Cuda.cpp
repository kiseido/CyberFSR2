#include "pch.h"
#include "NGX_Interposer.h"

bool CyberInterposer::PFN_Table_NVNGX_CUDA::LoadDLL(HMODULE hModule, bool populateChildren)
{
    CyberInterposer::logger.logVerboseInfo(__func__, "");

    if (hModule == nullptr)
    {
        return false;
    }

    pfn_cuInit = reinterpret_cast<PFN_NVSDK_NGX_CUDA_Init>(GetProcAddress(hModule, "cuInit"));
    pfn_cuInit_Ext = reinterpret_cast<PFN_NVSDK_NGX_CUDA_Init_Ext>(GetProcAddress(hModule, "cuInit_Ext"));
    pfn_cuInit_with_ProjectID = reinterpret_cast<PFN_NVSDK_NGX_CUDA_Init_with_ProjectID>(GetProcAddress(hModule, "cuInit_with_ProjectID"));

    pfn_cuShutdown = reinterpret_cast<PFN_NVSDK_NGX_CUDA_Shutdown>(GetProcAddress(hModule, "cuShutdown"));
    pfn_cuShutdown1 = reinterpret_cast<PFN_NVSDK_NGX_CUDA_Shutdown>(GetProcAddress(hModule, "cuShutdown1"));

    pfn_cuGetCapabilityParameters = reinterpret_cast<PFN_NVSDK_NGX_CUDA_GetCapabilityParameters>(GetProcAddress(hModule, "cuGetCapabilityParameters"));

    pfn_cuAllocateParameters = reinterpret_cast<PFN_NVSDK_NGX_CUDA_AllocateParameters>(GetProcAddress(hModule, "cuAllocateParameters"));
    pfn_cuDestroyParameters = reinterpret_cast<PFN_NVSDK_NGX_CUDA_DestroyParameters>(GetProcAddress(hModule, "cuDestroyParameters"));

    pfn_cuGetScratchBufferSize = reinterpret_cast<PFN_NVSDK_NGX_CUDA_GetScratchBufferSize>(GetProcAddress(hModule, "cuGetScratchBufferSize"));

    pfn_cuCreateFeature = reinterpret_cast<PFN_NVSDK_NGX_CUDA_CreateFeature>(GetProcAddress(hModule, "cuCreateFeature"));
    pfn_cuReleaseFeature = reinterpret_cast<PFN_NVSDK_NGX_CUDA_ReleaseFeature>(GetProcAddress(hModule, "cuReleaseFeature"));
    pfn_cuEvaluateFeature = reinterpret_cast<PFN_NVSDK_NGX_CUDA_EvaluateFeature>(GetProcAddress(hModule, "cuEvaluateFeature"));
    pfn_cuEvaluateFeature_C = reinterpret_cast<PFN_NVSDK_NGX_CUDA_EvaluateFeature_C>(GetProcAddress(hModule, "cuEvaluateFeature_C"));

    bool foundFunctions = true;

#define CyDLLLoadLog(name) \
	do { \
		const bool found = (name == nullptr); \
		if(found){ \
			CyberLOGi(#name, " found"); \
		} \
		else { \
			CyberLOGi(#name, " not found"); \
		} \
		foundFunctions = false; \
	} while(false)

    CyDLLLoadLog(pfn_cuInit);
    CyDLLLoadLog(pfn_cuInit_Ext);
    CyDLLLoadLog(pfn_cuInit_with_ProjectID);
    CyDLLLoadLog(pfn_cuShutdown);
    CyDLLLoadLog(pfn_cuShutdown1);
    CyDLLLoadLog(pfn_cuGetCapabilityParameters);
    CyDLLLoadLog(pfn_cuAllocateParameters);
    CyDLLLoadLog(pfn_cuDestroyParameters);
    CyDLLLoadLog(pfn_cuGetScratchBufferSize);
    CyDLLLoadLog(pfn_cuCreateFeature);
    CyDLLLoadLog(pfn_cuReleaseFeature);
    CyDLLLoadLog(pfn_cuEvaluateFeature);
    CyDLLLoadLog(pfn_cuEvaluateFeature_C);

#undef CyDLLLoadLog

    return foundFunctions;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_Init(unsigned long long a, const wchar_t* b, const NVSDK_NGX_FeatureCommonInfo* c, NVSDK_NGX_Version d) {
    CyberLOG();

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_CUDA.pfn_cuInit;

    if (ptr != nullptr)
        return ptr(a, b, c, d);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_Init_Ext(unsigned long long a , const wchar_t* b , const NVSDK_NGX_FeatureCommonInfo* c, NVSDK_NGX_Version d, unsigned long long e) {
    CyberLOG();

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_CUDA.pfn_cuInit_Ext;

    if (ptr != nullptr)
        return ptr(a, b, c, d, e);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_Init_with_ProjectID(const char* a, NVSDK_NGX_EngineType b, const char* c, const wchar_t* d, const NVSDK_NGX_FeatureCommonInfo* e, NVSDK_NGX_Version f) {
    CyberLOG();

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_CUDA.pfn_cuInit_with_ProjectID;

    if (ptr != nullptr)
        return ptr(a, b, c, d, e, f);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_Shutdown(void) {
    CyberLOG();

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_CUDA.pfn_cuShutdown;

    if (ptr != nullptr)
        return ptr();

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_Shutdown1(void) {
    CyberLOG();

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_CUDA.pfn_cuShutdown1;

    if (ptr != nullptr)
        return ptr();

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_GetCapabilityParameters(NVSDK_NGX_Parameter** a) {
    CyberLOG();

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_CUDA.pfn_cuGetCapabilityParameters;

    if (ptr != nullptr)
        return ptr(a);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_AllocateParameters(NVSDK_NGX_Parameter** a) {
    CyberLOG();

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_CUDA.pfn_cuAllocateParameters;

    if (ptr != nullptr)
        return ptr(a);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_DestroyParameters(NVSDK_NGX_Parameter* a) {
    CyberLOG();

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_CUDA.pfn_cuDestroyParameters;

    if (ptr != nullptr)
        return ptr(a);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_GetScratchBufferSize(NVSDK_NGX_Feature a, const NVSDK_NGX_Parameter* b, size_t* c) {
    CyberLOG();

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_CUDA.pfn_cuGetScratchBufferSize;

    if (ptr != nullptr)
        return ptr(a, b, c);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_CreateFeature(NVSDK_NGX_Feature a, const NVSDK_NGX_Parameter* b, NVSDK_NGX_Handle** c) {
    CyberLOG();

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_CUDA.pfn_cuCreateFeature;

    if (ptr != nullptr)
        return ptr(a, b, c);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_ReleaseFeature(NVSDK_NGX_Handle* a) {
    CyberLOG();

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_CUDA.pfn_cuReleaseFeature;

    if (ptr != nullptr)
        return ptr(a);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_EvaluateFeature(const NVSDK_NGX_Handle* a, const NVSDK_NGX_Parameter* b, PFN_NVSDK_NGX_ProgressCallback c) {
    CyberLOG();

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_CUDA.pfn_cuEvaluateFeature;

    if (ptr != nullptr)
        return ptr(a, b, c);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_CUDA_EvaluateFeature_C(const NVSDK_NGX_Handle* a, const NVSDK_NGX_Parameter* b, PFN_NVSDK_NGX_ProgressCallback_C c) {
    CyberLOG();

    auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_CUDA.pfn_cuEvaluateFeature_C;

    if (ptr != nullptr)
        return ptr(a, b, c);

    return NVSDK_NGX_Result_Fail;
}
