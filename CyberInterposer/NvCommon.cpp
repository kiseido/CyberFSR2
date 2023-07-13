#include "pch.h"
#include "NvCommon.h"
#include "Interposer.h"
#include "Logger.h"

using namespace Interposer;

void NvParameter::Set(const char* InName, unsigned long long InValue)
{
    CyberLOG();
    if (pfn_SetULL != nullptr)
        reinterpret_cast<void(*)(const char*, unsigned long long)>(pfn_SetULL)(InName, InValue);
}

void NvParameter::Set(const char* InName, float InValue)
{
    CyberLOG();
    if (pfn_SetF != nullptr)
        reinterpret_cast<void(*)(const char*, float)>(pfn_SetF)(InName, InValue);
}

void NvParameter::Set(const char* InName, double InValue)
{
    CyberLOG();
    if (pfn_SetD != nullptr)
        reinterpret_cast<void(*)(const char*, double)>(pfn_SetD)(InName, InValue);
}

void NvParameter::Set(const char* InName, unsigned int InValue)
{
    CyberLOG();
    if (pfn_SetUI != nullptr)
        reinterpret_cast<void(*)(const char*, unsigned int)>(pfn_SetUI)(InName, InValue);
}

void NvParameter::Set(const char* InName, int InValue)
{
    CyberLOG();
    if (pfn_SetI != nullptr)
        reinterpret_cast<void(*)(const char*, int)>(pfn_SetI)(InName, InValue);
}

void NvParameter::Set(const char* InName, ID3D11Resource* InValue)
{
    CyberLOG();
    if (pfn_SetD3d11Resource != nullptr)
        reinterpret_cast<void(*)(const char*, ID3D11Resource*)>(pfn_SetD3d11Resource)(InName, InValue);
}

void NvParameter::Set(const char* InName, ID3D12Resource* InValue)
{
    CyberLOG();
    if (pfn_SetD3d12Resource != nullptr)
        reinterpret_cast<void(*)(const char*, ID3D12Resource*)>(pfn_SetD3d12Resource)(InName, InValue);
}

void NvParameter::Set(const char* InName, void* InValue)
{
    CyberLOG();
    if (pfn_SetVoidPointer != nullptr)
        reinterpret_cast<void(*)(const char*, void*)>(pfn_SetVoidPointer)(InName, InValue);
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, unsigned long long* OutValue) const
{
    CyberLOG();
    if (pfn_GetULL != nullptr)
        return reinterpret_cast<NVSDK_NGX_Result(*)(const char*, unsigned long long*)>(pfn_GetULL)(InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, float* OutValue) const
{
    CyberLOG();
    if (pfn_GetF != nullptr)
        return reinterpret_cast<NVSDK_NGX_Result(*)(const char*, float*)>(pfn_GetF)(InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, double* OutValue) const
{
    CyberLOG();
    if (pfn_GetD != nullptr)
        return reinterpret_cast<NVSDK_NGX_Result(*)(const char*, double*)>(pfn_GetD)(InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, unsigned int* OutValue) const
{
    CyberLOG();
    if (pfn_GetUI != nullptr)
        return reinterpret_cast<NVSDK_NGX_Result(*)(const char*, unsigned int*)>(pfn_GetUI)(InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, int* OutValue) const
{
    CyberLOG();
    if (pfn_GetI != nullptr)
        return reinterpret_cast<NVSDK_NGX_Result(*)(const char*, int*)>(pfn_GetI)(InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, ID3D11Resource** OutValue) const
{
    CyberLOG();
    if (pfn_GetD3d11Resource != nullptr)
        return reinterpret_cast<NVSDK_NGX_Result(*)(const char*, ID3D11Resource**)>(pfn_GetD3d11Resource)(InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, ID3D12Resource** OutValue) const
{
    CyberLOG();
    if (pfn_GetD3d12Resource != nullptr)
        return reinterpret_cast<NVSDK_NGX_Result(*)(const char*, ID3D12Resource**)>(pfn_GetD3d12Resource)(InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NvParameter::Get(const char* InName, void** OutValue) const
{
    CyberLOG();
    if (pfn_GetVoidPointer != nullptr)
        return reinterpret_cast<NVSDK_NGX_Result(*)(const char*, void**)>(pfn_GetVoidPointer)(InName, OutValue);

    return NVSDK_NGX_Result_Fail;
}
