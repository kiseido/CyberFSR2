#include "pch.h"
#include "NGX_Interposer.h"

using namespace CyberInterposer;

CyberInterposer::PFN_Table_NVNGX_Parameter::PFN_Table_NVNGX_Parameter(NVSDK_NGX_Parameter& other)
{
    std::memcpy(original.data(), &other, sizeof(NVSDK_NGX_Parameter));

}


/*
bool CyberInterposer::PFN_Table_NVNGX_Parameter::LoadDLL(HMODULE inputFile, bool populateChildren)
{
    CyberLogArgs(inputFile, populateChildren);

    if (inputFile == nullptr || inputFile == 0) {
        CyberLOGe("hModule is bad");
        return false;
    }

    // common
    pfn_GetULL = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetULL>(GetProcAddress(inputFile, "GetULL"));
    pfn_SetULL = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetULL>(GetProcAddress(inputFile, "SetULL"));
    pfn_GetD = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetD>(GetProcAddress(inputFile, "GetD"));
    pfn_SetD = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetD>(GetProcAddress(inputFile, "SetD"));
    pfn_GetI = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetI>(GetProcAddress(inputFile, "GetI"));
    pfn_SetI = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetI>(GetProcAddress(inputFile, "SetI"));
    pfn_SetVoidPointer = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetVoidPointer>(GetProcAddress(inputFile, "SetVoidPointer"));
    pfn_GetVoidPointer = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetVoidPointer>(GetProcAddress(inputFile, "GetVoidPointer"));
    pfn_GetF = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetF>(GetProcAddress(inputFile, "GetF"));
    pfn_SetF = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetF>(GetProcAddress(inputFile, "SetF"));
    pfn_GetUI = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetUI>(GetProcAddress(inputFile, "GetUI"));
    pfn_SetUI = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetUI>(GetProcAddress(inputFile, "SetUI"));

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


    CyDLLLoadLog(pfn_GetULL);
    CyDLLLoadLog(pfn_SetULL);
    CyDLLLoadLog(pfn_GetD);
    CyDLLLoadLog(pfn_SetD);
    CyDLLLoadLog(pfn_GetI);
    CyDLLLoadLog(pfn_SetI);
    CyDLLLoadLog(pfn_SetVoidPointer);
    CyDLLLoadLog(pfn_GetVoidPointer);
    CyDLLLoadLog(pfn_GetF);
    CyDLLLoadLog(pfn_SetF);
    CyDLLLoadLog(pfn_GetUI);
    CyDLLLoadLog(pfn_SetUI);

#undef CyDLLLoadLog

    return foundFunctions;
}
*/



void CI_NGX_Parameter::Set(const char* InName, unsigned long long InValue)
{
    CyberLogArgs(InName, InValue);

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_SetULL;

    if (ptr != nullptr)
        ptr(this, InName, InValue);
}

void CI_NGX_Parameter::Set(const char* InName, float InValue)
{
    CyberLogArgs(InName, InValue);

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_SetF;

    if (ptr != nullptr)
        ptr(this, InName, InValue);
}

void CI_NGX_Parameter::Set(const char* InName, double InValue)
{
    CyberLogArgs(InName, InValue);

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_SetD;

    if (ptr != nullptr)
        ptr(this, InName, InValue);
}

void CI_NGX_Parameter::Set(const char* InName, unsigned int InValue)
{
    CyberLogArgs(InName, InValue);

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_SetUI;

    if (ptr != nullptr)
        ptr(this, InName, InValue);
}

void CI_NGX_Parameter::Set(const char* InName, int InValue)
{
    CyberLogArgs(InName, InValue);

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_SetI;

    if (ptr != nullptr)
        ptr(this, InName, InValue);
}

void CI_NGX_Parameter::Set(const char* InName, ID3D11Resource* InValue)
{
    CyberLogArgs(InName, InValue);

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_SetD3d11Resource;

    if (ptr != nullptr)
        ptr(this, InName, InValue);
}

void CI_NGX_Parameter::Set(const char* InName, ID3D12Resource* InValue)
{
    CyberLogArgs(InName, InValue);

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_SetD3d12Resource;

    if (ptr != nullptr)
        ptr(this, InName, InValue);
}

void CI_NGX_Parameter::Set(const char* InName, void* InValue)
{
    CyberLogArgs(InName, InValue);

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_SetVoidPointer;

    if (ptr != nullptr)
        ptr(this, InName, InValue);
}

NVSDK_NGX_Result CI_NGX_Parameter::Get(const char* InName, unsigned long long* OutValue) const
{
    CyberLogArgs(InName, OutValue);

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_GetULL;

    if (ptr != nullptr)
        return ptr((NVSDK_NGX_Parameter* const) this, InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result CI_NGX_Parameter::Get(const char* InName, float* OutValue) const
{
    CyberLogArgs(InName, OutValue);

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_GetF;

    if (ptr != nullptr)
        return ptr((NVSDK_NGX_Parameter* const) this, InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result CI_NGX_Parameter::Get(const char* InName, double* OutValue) const
{
    CyberLogArgs(InName, OutValue);

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_GetD;

    if (ptr != nullptr)
        return ptr((NVSDK_NGX_Parameter* const) this, InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result CI_NGX_Parameter::Get(const char* InName, unsigned int* OutValue) const
{
    CyberLogArgs(InName, OutValue);

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_GetUI;

    if (ptr != nullptr)
        return ptr((NVSDK_NGX_Parameter* const) this, InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result CI_NGX_Parameter::Get(const char* InName, int* OutValue) const
{
    CyberLogArgs(InName, OutValue);

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_GetI;

    if (ptr != nullptr)
        return ptr((NVSDK_NGX_Parameter* const) this, InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result CI_NGX_Parameter::Get(const char* InName, ID3D11Resource** OutValue) const
{
    CyberLogArgs(InName, OutValue);

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_GetD3d11Resource;

    if (ptr != nullptr)
        return ptr((NVSDK_NGX_Parameter* const) this, InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result CI_NGX_Parameter::Get(const char* InName, ID3D12Resource** OutValue) const
{
    CyberLogArgs(InName, OutValue);

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_GetD3d12Resource;

    if (ptr != nullptr)
        return ptr((NVSDK_NGX_Parameter* const) this, InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result CI_NGX_Parameter::Get(const char* InName, void** OutValue) const
{
    CyberLogArgs(InName, OutValue);

    auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_Parameter.pfn_GetVoidPointer;

    if (ptr != nullptr)
        return ptr((NVSDK_NGX_Parameter* const) this, InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

void CI_NGX_Parameter::Reset()
{
    CyberLOG();
}

