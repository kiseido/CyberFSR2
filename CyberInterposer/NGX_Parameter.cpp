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
#ifdef CyberInterposer_DO_DX11
    CyberLogArgs(InName, InValue);

    wrapped.param->Set(InName, InValue);

    return;
#endif
#ifndef CyberInterposer_DO_DX11
    return;
#endif
}

void CI_NGX_Parameter::Set(const char* InName, ID3D12Resource* InValue)
{
#ifdef CyberInterposer_DO_DX12
    CyberLogArgs(InName, InValue);

    wrapped.param->Set(InName, InValue);

    return;
#endif
#ifndef CyberInterposer_DO_DX12
        return;
#endif
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
#ifdef CyberInterposer_DO_DX11
    //CyberLogArgs(InName, OutValue);

    auto result = wrapped.param->Get(InName, OutValue);

    CyberLOGvi(InName, OutValue, result);

    return result;
#endif
#ifndef CyberInterposer_DO_DX11
    return NVSDK_NGX_Result_Fail;
#endif
}

NVSDK_NGX_Result CI_NGX_Parameter::Get(const char* InName, ID3D12Resource** OutValue) const
{
#ifdef CyberInterposer_DO_DX12
    //CyberLogArgs(InName, OutValue);

    auto result = wrapped.param->Get(InName, OutValue);

    CyberLOGvi(InName, OutValue, result);

    return result;
#endif
#ifndef CyberInterposer_DO_DX12
    return NVSDK_NGX_Result_Fail;
#endif
}

NVSDK_NGX_Result CI_NGX_Parameter::Get(const char* InName, void** OutValue) const
{
    CyberLogArgs(InName, OutValue);

    constexpr const char* OptimalCallbaskStr = NGX_String_Converter::NGX_Strings_macrocontent[(int)NGX_String_Converter::NVSDK_NGX_Parameter_DLSSOptimalSettingsCallback_enum].data();

    constexpr const char* StatsCallbaskStr = NGX_String_Converter::NGX_Strings_macrocontent[(int)NGX_String_Converter::NVSDK_NGX_Parameter_DLSSGetStatsCallback_enum].data();

    const auto isOptimalSettingsCallback = strcmp(InName, OptimalCallbaskStr);

    if (isOptimalSettingsCallback == 0) {
        void** interim = nullptr;
        auto result = wrapped.param->Get(InName, interim);
        this->wrapped_GetOptimalSettingsCallback = (GetOptimalSettingsCallbackType*) *interim;
        return result;
    }

    const auto isStatsCallback = strcmp(InName, StatsCallbaskStr);

    if (isStatsCallback == 0) {
        void** interim = nullptr;
        auto result = wrapped.param->Get(InName, interim);
        this->wrapped_GetStatsCallback = (GetStatsCallbackType*) *interim;
        return result;
    }
    
    return wrapped.param->Get(InName, OutValue);
}

void CI_NGX_Parameter::Reset()
{
    CyberLOG();

    wrapped.param->Reset();
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetOptimalSettingsCallback(NVSDK_NGX_Parameter* InParams)
{
    return ((CI_NGX_Parameter*)InParams)->GetOptimalSettingsCallback();
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetStatsCallback(NVSDK_NGX_Parameter* InParams)
{
    return ((CI_NGX_Parameter*)InParams)->GetStatsCallback();
}

NVSDK_NGX_Result CyberInterposer::CI_NGX_Parameter::GetOptimalSettingsCallback() {
    const GetOptimalSettingsCallbackType* callback = this->wrapped_GetOptimalSettingsCallback;
    return (*callback)(this->wrapped.param);
}
NVSDK_NGX_Result CyberInterposer::CI_NGX_Parameter::GetStatsCallback() {
    const GetStatsCallbackType* callback = this->wrapped_GetStatsCallback;
    return (*callback)(this->wrapped.param);
}

CyberInterposer::CI_NGX_Parameter::CI_NGX_Parameter() {}

CyberInterposer::CI_NGX_Parameter::CI_NGX_Parameter(NVSDK_NGX_Parameter* other) : wrapped(other) {}

CyberInterposer::PFN_Table_NVNGX_Parameter_Union_P::PFN_Table_NVNGX_Parameter_Union_P(NVSDK_NGX_Parameter* other) : param(other) {}

CyberInterposer::PFN_Table_NVNGX_Parameter_Union_P::PFN_Table_NVNGX_Parameter_Union_P() : param(nullptr) {};

CI_MGX_Parameter_StaticAlloc CI_MGX_Parameter_StaticAlloc::GetParameters_depreciated = {};
CI_MGX_Parameter_StaticAlloc CI_MGX_Parameter_StaticAlloc::AllocateParameters = {};

CI_NGX_Parameter* CI_MGX_Parameter_StaticAlloc::claim() noexcept(false) {
    std::lock_guard<std::mutex> lock(allocatorMutex);

    for (std::size_t i = 0; i < PoolSize; ++i) {
        if (!freeSlots.test(i)) {
            freeSlots.set(i);
            return &memoryPool[i];
        }
    }

    throw std::runtime_error("No free slots available.");
}

CI_NGX_Parameter* CI_MGX_Parameter_StaticAlloc::claim(std::size_t number) noexcept(false) {
    if (number == 0 || number > PoolSize) {
        throw std::invalid_argument("Invalid number to claim.");
    }

    std::lock_guard<std::mutex> lock(allocatorMutex);

    for (std::size_t i = 0; i <= PoolSize - number; ++i) {
        bool canAllocate = true;

        for (std::size_t j = 0; j < number; ++j) {
            if (freeSlots.test(i + j)) {
                canAllocate = false;
                break;
            }
        }

        if (canAllocate) {
            for (std::size_t j = 0; j < number; ++j) {
                freeSlots.set(i + j);
            }

            return &memoryPool[i];
        }
    }

    throw std::runtime_error("No contiguous slots of the requested size available.");
}

bool CI_MGX_Parameter_StaticAlloc::release(CI_NGX_Parameter* p) noexcept(false) {
    std::lock_guard<std::mutex> lock(allocatorMutex);

    std::ptrdiff_t index = p - memoryPool.data();

    if (index < 0 || index >= static_cast<std::ptrdiff_t>(PoolSize) || !freeSlots.test(index)) {
        throw std::invalid_argument("Invalid pointer or not currently claimed.");
    }

    freeSlots.reset(index);
    return true;
}

bool CI_MGX_Parameter_StaticAlloc::release(CI_NGX_Parameter* p, std::size_t number) noexcept(false) {
    if (number == 0 || number > PoolSize) {
        throw std::invalid_argument("Invalid number to release.");
    }

    std::lock_guard<std::mutex> lock(allocatorMutex);

    std::ptrdiff_t index = p - memoryPool.data();

    if (index < 0 || index + number > static_cast<std::ptrdiff_t>(PoolSize)) {
        throw std::invalid_argument("Invalid pointer range.");
    }

    for (std::size_t i = 0; i < number; ++i) {
        if (!freeSlots.test(index + i)) {
            throw std::invalid_argument("Some of the pointers are not currently claimed.");
        }

        freeSlots.reset(index + i);
    }

    return true;
}

// Initialization of the free slots
CI_MGX_Parameter_StaticAlloc::CI_MGX_Parameter_StaticAlloc() {
    freeSlots.reset();
}