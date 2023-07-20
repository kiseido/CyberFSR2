#include "pch.h"
#include "NGX_Interposer.h"

using namespace CyberInterposer;


void NVSDK_CONV NvParameter::Set(const char* InName, unsigned long long InValue)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_SetULL;

    if (ptr != nullptr)
        ptr(this, InName, InValue);
}

void NVSDK_CONV NvParameter::Set(const char* InName, float InValue)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_SetF;

    if (ptr != nullptr)
        ptr(this, InName, InValue);
}

void NVSDK_CONV NvParameter::Set(const char* InName, double InValue)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_SetD;

    if (ptr != nullptr)
        ptr(this, InName, InValue);
}

void NVSDK_CONV NvParameter::Set(const char* InName, unsigned int InValue)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_SetUI;

    if (ptr != nullptr)
        ptr(this, InName, InValue);
}

void NVSDK_CONV NvParameter::Set(const char* InName, int InValue)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_SetI;

    if (ptr != nullptr)
        ptr(this, InName, InValue);
}

void NVSDK_CONV NvParameter::Set(const char* InName, ID3D11Resource* InValue)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_SetD3d11Resource;

    if (ptr != nullptr)
        ptr(this, InName, InValue);
}

void NVSDK_CONV NvParameter::Set(const char* InName, ID3D12Resource* InValue)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_SetD3d12Resource;

    if (ptr != nullptr)
        ptr(this, InName, InValue);
}

void NVSDK_CONV NvParameter::Set(const char* InName, void* InValue)
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_SetVoidPointer;

    if (ptr != nullptr)
        ptr(this, InName, InValue);
}

NVSDK_NGX_Result NVSDK_CONV NvParameter::Get(const char* InName, unsigned long long* OutValue) const
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_GetULL;

    if (ptr != nullptr)
        return ptr((NVSDK_NGX_Parameter* const) this, InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NvParameter::Get(const char* InName, float* OutValue) const
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_GetF;

    if (ptr != nullptr)
        return ptr((NVSDK_NGX_Parameter* const) this, InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NvParameter::Get(const char* InName, double* OutValue) const
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_GetD;

    if (ptr != nullptr)
        return ptr((NVSDK_NGX_Parameter* const) this, InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NvParameter::Get(const char* InName, unsigned int* OutValue) const
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_GetUI;

    if (ptr != nullptr)
        return ptr((NVSDK_NGX_Parameter* const) this, InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NvParameter::Get(const char* InName, int* OutValue) const
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_GetI;

    if (ptr != nullptr)
        return ptr((NVSDK_NGX_Parameter* const) this, InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NvParameter::Get(const char* InName, ID3D11Resource** OutValue) const
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_GetD3d11Resource;

    if (ptr != nullptr)
        return ptr((NVSDK_NGX_Parameter* const) this, InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NvParameter::Get(const char* InName, ID3D12Resource** OutValue) const
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_GetD3d12Resource;

    if (ptr != nullptr)
        return ptr((NVSDK_NGX_Parameter* const) this, InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NvParameter::Get(const char* InName, void** OutValue) const
{
    CyberLOG();

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_GetVoidPointer;

    if (ptr != nullptr)
        return ptr((NVSDK_NGX_Parameter* const) this, InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

bool CyberInterposer::PFN_Table_NVNGX_Parameter::LoadDLL(HMODULE inputFile, bool populateChildren)
{
    CyberLogArgs(inputFile, populateChildren);

    if (inputFile == nullptr || inputFile == 0) {
        CyberLOGy("hModule is bad");
        return false;
    }

    // common
    pfn_GetULL = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetULL>(GetProcAddress(inputFile, "NVSDK_NGX_Parameter_GetULL"));
    pfn_SetULL = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetULL>(GetProcAddress(inputFile, "NVSDK_NGX_Parameter_SetULL"));
    pfn_GetD = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetD>(GetProcAddress(inputFile, "NVSDK_NGX_Parameter_GetD"));
    pfn_SetD = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetD>(GetProcAddress(inputFile, "NVSDK_NGX_Parameter_SetD"));
    pfn_GetI = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetI>(GetProcAddress(inputFile, "NVSDK_NGX_Parameter_GetI"));
    pfn_SetI = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetI>(GetProcAddress(inputFile, "NVSDK_NGX_Parameter_SetI"));
    pfn_SetVoidPointer = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetVoidPointer>(GetProcAddress(inputFile, "NVSDK_NGX_Parameter_SetVoidPointer"));
    pfn_GetVoidPointer = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetVoidPointer>(GetProcAddress(inputFile, "NVSDK_NGX_Parameter_GetVoidPointer"));
    pfn_GetF = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetF>(GetProcAddress(inputFile, "NVSDK_NGX_Parameter_GetF"));
    pfn_SetF = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetF>(GetProcAddress(inputFile, "NVSDK_NGX_Parameter_SetF"));
    pfn_GetUI = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetUI>(GetProcAddress(inputFile, "NVSDK_NGX_Parameter_GetUI"));
    pfn_SetUI = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetUI>(GetProcAddress(inputFile, "NVSDK_NGX_Parameter_SetUI"));

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
        CyberLOGy("NVNGX Parameter functions not found");
        return false;
    }

    return true;
}
