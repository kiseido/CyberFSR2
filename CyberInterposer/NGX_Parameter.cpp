#include "pch.h"
#include "NGX_Interposer.h"

using namespace CyberInterposer;

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

    wrapped.param->Set(InName, InValue);

    return;
}

void CI_NGX_Parameter::Set(const char* InName, float InValue)
{
    CyberLogArgs(InName, InValue);

    wrapped.param->Set(InName, InValue);

    return;
}

void CI_NGX_Parameter::Set(const char* InName, double InValue)
{
    CyberLogArgs(InName, InValue);

    wrapped.param->Set(InName, InValue);

    return;
}

void CI_NGX_Parameter::Set(const char* InName, unsigned int InValue)
{
    CyberLogArgs(InName, InValue);

    wrapped.param->Set(InName, InValue);

    return;
}

void CI_NGX_Parameter::Set(const char* InName, int InValue)
{
    CyberLogArgs(InName, InValue);

    wrapped.param->Set(InName, InValue);

    return;
}

void CI_NGX_Parameter::Set(const char* InName, ID3D11Resource* InValue)
{
    CyberLogArgs(InName, InValue);

    wrapped.param->Set(InName, InValue);

    return;
}

void CI_NGX_Parameter::Set(const char* InName, ID3D12Resource* InValue)
{
    CyberLogArgs(InName, InValue);

    wrapped.param->Set(InName, InValue);

    return;
}

void CI_NGX_Parameter::Set(const char* InName, void* InValue)
{
    CyberLogArgs(InName, InValue);

    wrapped.param->Set(InName, InValue);

    return;
}

NVSDK_NGX_Result CI_NGX_Parameter::Get(const char* InName, unsigned long long* OutValue) const
{
    CyberLogArgs(InName, OutValue);

    return wrapped.param->Get(InName, OutValue);
}

NVSDK_NGX_Result CI_NGX_Parameter::Get(const char* InName, float* OutValue) const
{
    CyberLogArgs(InName, OutValue);

    return wrapped.param->Get(InName, OutValue);
}

NVSDK_NGX_Result CI_NGX_Parameter::Get(const char* InName, double* OutValue) const
{
    CyberLogArgs(InName, OutValue);

    return wrapped.param->Get(InName, OutValue);
}

NVSDK_NGX_Result CI_NGX_Parameter::Get(const char* InName, unsigned int* OutValue) const
{
    CyberLogArgs(InName, OutValue);

    return wrapped.param->Get(InName, OutValue);
}

NVSDK_NGX_Result CI_NGX_Parameter::Get(const char* InName, int* OutValue) const
{
    CyberLogArgs(InName, OutValue);

    return wrapped.param->Get(InName, OutValue);
}

NVSDK_NGX_Result CI_NGX_Parameter::Get(const char* InName, ID3D11Resource** OutValue) const
{
    CyberLogArgs(InName, OutValue);

    return wrapped.param->Get(InName, OutValue);
}

NVSDK_NGX_Result CI_NGX_Parameter::Get(const char* InName, ID3D12Resource** OutValue) const
{
    CyberLogArgs(InName, OutValue);

    return wrapped.param->Get(InName, OutValue);
}

NVSDK_NGX_Result CI_NGX_Parameter::Get(const char* InName, void** OutValue) const
{
    CyberLogArgs(InName, OutValue);

    return wrapped.param->Get(InName, OutValue);
}

void CI_NGX_Parameter::Reset()
{
    CyberLOG();

    wrapped.param->Reset();
}

CyberInterposer::CI_NGX_Parameter::CI_NGX_Parameter(NVSDK_NGX_Parameter* other) : wrapped(other){}

CyberInterposer::PFN_Table_NVNGX_Parameter_Union_P::PFN_Table_NVNGX_Parameter_Union_P(NVSDK_NGX_Parameter* other) : param(other){}
