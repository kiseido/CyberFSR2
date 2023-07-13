#include "pch.h"
#include "NvCommon.h"
#include "Interposer.h"
#include "Logger.h"

using namespace CyberInterposer;

void NvParameter::Set(const char* InName, unsigned long long InValue)
{
    CyberLOG();
    if (function_table.pfn_SetULL != nullptr)
        reinterpret_cast<void(*)(const char*, unsigned long long)>(function_table.pfn_SetULL)(InName, InValue);
}

void NvParameter::Set(const char* InName, float InValue)
{
    CyberLOG();
    if (function_table.pfn_SetF != nullptr)
        reinterpret_cast<void(*)(const char*, float)>(function_table.pfn_SetF)(InName, InValue);
}

void NvParameter::Set(const char* InName, double InValue)
{
    CyberLOG();
    if (function_table.pfn_SetD != nullptr)
        reinterpret_cast<void(*)(const char*, double)>(function_table.pfn_SetD)(InName, InValue);
}

void NvParameter::Set(const char* InName, unsigned int InValue)
{
    CyberLOG();
    if (function_table.pfn_SetUI != nullptr)
        reinterpret_cast<void(*)(const char*, unsigned int)>(function_table.pfn_SetUI)(InName, InValue);
}

void NvParameter::Set(const char* InName, int InValue)
{
    CyberLOG();
    if (function_table.pfn_SetI != nullptr)
        reinterpret_cast<void(*)(const char*, int)>(function_table.pfn_SetI)(InName, InValue);
}

void NvParameter::Set(const char* InName, ID3D11Resource* InValue)
{
    CyberLOG();
    if (function_table.pfn_SetD3d11Resource != nullptr)
        reinterpret_cast<void(*)(const char*, ID3D11Resource*)>(function_table.pfn_SetD3d11Resource)(InName, InValue);
}

void NvParameter::Set(const char* InName, ID3D12Resource* InValue)
{
    CyberLOG();
    if (function_table.pfn_SetD3d12Resource != nullptr)
        reinterpret_cast<void(*)(const char*, ID3D12Resource*)>(function_table.pfn_SetD3d12Resource)(InName, InValue);
}

void NvParameter::Set(const char* InName, void* InValue)
{
    CyberLOG();
    if (function_table.pfn_SetVoidPointer != nullptr)
        reinterpret_cast<void(*)(const char*, void*)>(function_table.pfn_SetVoidPointer)(InName, InValue);
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, unsigned long long* OutValue) const
{
    CyberLOG();
    if (function_table.pfn_GetULL != nullptr)
        return reinterpret_cast<NVSDK_NGX_Result(*)(const char*, unsigned long long*)>(function_table.pfn_GetULL)(InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, float* OutValue) const
{
    CyberLOG();
    if (function_table.pfn_GetF != nullptr)
        return reinterpret_cast<NVSDK_NGX_Result(*)(const char*, float*)>(function_table.pfn_GetF)(InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, double* OutValue) const
{
    CyberLOG();
    if (function_table.pfn_GetD != nullptr)
        return reinterpret_cast<NVSDK_NGX_Result(*)(const char*, double*)>(function_table.pfn_GetD)(InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, unsigned int* OutValue) const
{
    CyberLOG();
    if (function_table.pfn_GetUI != nullptr)
        return reinterpret_cast<NVSDK_NGX_Result(*)(const char*, unsigned int*)>(function_table.pfn_GetUI)(InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, int* OutValue) const
{
    CyberLOG();
    if (function_table.pfn_GetI != nullptr)
        return reinterpret_cast<NVSDK_NGX_Result(*)(const char*, int*)>(function_table.pfn_GetI)(InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, ID3D11Resource** OutValue) const
{
    CyberLOG();
    if (function_table.pfn_GetD3d11Resource != nullptr)
        return reinterpret_cast<NVSDK_NGX_Result(*)(const char*, ID3D11Resource**)>(function_table.pfn_GetD3d11Resource)(InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, ID3D12Resource** OutValue) const
{
    CyberLOG();
    if (function_table.pfn_GetD3d12Resource != nullptr)
        return reinterpret_cast<NVSDK_NGX_Result(*)(const char*, ID3D12Resource**)>(function_table.pfn_GetD3d12Resource)(InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, void** OutValue) const
{
    CyberLOG();
    if (function_table.pfn_GetVoidPointer != nullptr)
        return reinterpret_cast<NVSDK_NGX_Result(*)(const char*, void**)>(function_table.pfn_GetVoidPointer)(InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}
