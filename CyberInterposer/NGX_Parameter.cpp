#include "pch.h"
#include <format>
#include "NGX_Interposer.h"

namespace CyberInterposer {
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
    template<typename T>
    consteval std::wstring_view TypeString() {
        constexpr SIZE_T strLengthMax = 5;
        if constexpr (std::is_same_v<T, unsigned long long> ||
            std::is_same_v<T, unsigned long long*>) {
            return L"ULL  ";
        }
        else if constexpr (std::is_same_v<T, float> ||
            std::is_same_v<T, float*>) {
            return L"FLOAT";
        }
        else if constexpr (std::is_same_v<T, double> ||
            std::is_same_v<T, double*>) {
            return L"DOUBLE";
        }
        else if constexpr (std::is_same_v<T, unsigned int> ||
            std::is_same_v<T, unsigned int*>) {
            return L"UINT  ";
        }
        else if constexpr (std::is_same_v<T, int> ||
            std::is_same_v<T, int*>) {
            return L"INT  ";
        }
        else if constexpr (std::is_same_v<T, void*> ||
            std::is_same_v<T, void**>) {
            return L"VOIDP";
        }
        else if constexpr (std::is_same_v<T, ID3D11Resource*> ||
            std::is_same_v<T, ID3D11Resource**>) {
            return L"D11RP";
        }
        else if constexpr (std::is_same_v<T, ID3D12Resource*> ||
            std::is_same_v<T, ID3D12Resource**>) {
            return L"D12RP";
        }
        else {
            return L"UNKN ";
        }
    }

    void CI_Parameter::Set(const char* InName, void* InValue)
    {
        const std::wstring_view typeString = TypeString<void*>();

        CyberLogArgs(InName, InValue, typeString);

        wrapped.param->Set(InName, InValue);

        return;
    }

    template<typename T>
    void CI_Parameter::SetHelper(const char* InName, T InValue)
    {
        const std::wstring_view typeString = TypeString<T>();

        CyberLogArgs(InName, InValue, typeString);

        wrapped.param->Set(InName, InValue);

        return;
    }

    void CI_Parameter::Set(const char* InName, unsigned long long InValue)
    {
        SetHelper(InName, InValue);
    }

    void CI_Parameter::Set(const char* InName, float InValue)
    {
        SetHelper(InName, InValue);
    }

    void CI_Parameter::Set(const char* InName, double InValue)
    {
        SetHelper(InName, InValue);
    }

    void CI_Parameter::Set(const char* InName, unsigned int InValue)
    {
        SetHelper(InName, InValue);
    }

    void CI_Parameter::Set(const char* InName, int InValue)
    {
        SetHelper(InName, InValue);
    }

    void CI_Parameter::Set(const char* InName, ID3D11Resource* InValue)
    {
        SetHelper(InName, InValue);
    }

    void CI_Parameter::Set(const char* InName, ID3D12Resource* InValue)
    {
        SetHelper(InName, InValue);
    }

    NVSDK_NGX_Result CI_Parameter::Get(const char* InName, void** OutValue) const
    {
        const auto& converter = CyberNGX::NGX_Strings::StringsConverter;
        using enumSpace = CyberNGX::NGX_Strings::MacroStrings_enum;

        const auto OptimalCallbackStr = converter.getContentFromEnum(enumSpace::NVSDK_NGX_Parameter_DLSSOptimalSettingsCallback_enum).data();
        const auto StatsCallbackStr = converter.getContentFromEnum(enumSpace::NVSDK_NGX_Parameter_DLSSGetStatsCallback_enum).data();

        NVSDK_NGX_Result result = NVSDK_NGX_Result(0b0);

        if (strcmp(InName, OptimalCallbackStr) == 0) {
            auto interim = nullptr;
            result = wrapped.param->Get(InName, (void**)&interim);
            this->wrapped_GetOptimalSettingsCallback = interim;
            *OutValue = GetOptimalSettingsCallback;
        }
        else if (strcmp(InName, StatsCallbackStr) == 0) {
            auto interim = nullptr;
            result = wrapped.param->Get(InName, (void**)&interim);
            this->wrapped_GetStatsCallback = interim;
            *OutValue = GetStatsCallback;
        }
        else {
            result = wrapped.param->Get(InName, OutValue);
            CyberLOGvi(L"VOIDP", InName, OutValue, result);
        }

        return result;
    }


    template<typename T>
    NVSDK_NGX_Result CI_Parameter::GetHelper(const char* InName, T* OutValue) const
    {
        const auto result = wrapped.param->Get(InName, OutValue);

        const std::wstring_view typeString = TypeString<T>();

        CyberLogArgs(InName, *OutValue, typeString, result);

        return result;
    }


    NVSDK_NGX_Result CI_Parameter::Get(const char* InName, unsigned long long* OutValue) const
    {
        return GetHelper(InName, OutValue);
    }

    NVSDK_NGX_Result CI_Parameter::Get(const char* InName, float* OutValue) const
    {
        return GetHelper(InName, OutValue);
    }

    NVSDK_NGX_Result CI_Parameter::Get(const char* InName, double* OutValue) const
    {
        return GetHelper(InName, OutValue);
    }

    NVSDK_NGX_Result CI_Parameter::Get(const char* InName, unsigned int* OutValue) const
    {
        return GetHelper(InName, OutValue);
    }

    NVSDK_NGX_Result CI_Parameter::Get(const char* InName, int* OutValue) const
    {
        return GetHelper(InName, OutValue);
    }

    NVSDK_NGX_Result CI_Parameter::Get(const char* InName, ID3D11Resource** OutValue) const
    {
        return GetHelper(InName, OutValue);
    }

    NVSDK_NGX_Result CI_Parameter::Get(const char* InName, ID3D12Resource** OutValue) const
    {
        return GetHelper(InName, OutValue);
    }

    void CI_Parameter::Reset()
    {
        CyberLOG();

        wrapped.param->Reset();
    }


    NVSDK_NGX_Result CALLBACK CyberInterposer::CI_Parameter::GetOptimalSettingsCallback(CI_Parameter* inParam) {
        const auto& callback = inParam->wrapped_GetOptimalSettingsCallback;

        NVSDK_NGX_Result result = NVSDK_NGX_Result_Fail;

        if(callback)
            result = (callback)(inParam->wrapped.param);

        return result;
    }
    NVSDK_NGX_Result CALLBACK CyberInterposer::CI_Parameter::GetStatsCallback(CI_Parameter* inParam) {
        const auto& callback = inParam->wrapped_GetStatsCallback;

        NVSDK_NGX_Result result = NVSDK_NGX_Result_Fail;

        if (callback)
            result = (callback)(inParam->wrapped.param);

        return result;
    }

    CyberInterposer::CI_Parameter::CI_Parameter() {}

    CyberInterposer::CI_Parameter::CI_Parameter(NVSDK_NGX_Parameter* other) : wrapped(other) {}

    CyberInterposer::PFN_Table_NVNGX_Parameter_Union_P::PFN_Table_NVNGX_Parameter_Union_P(NVSDK_NGX_Parameter* other) : param(other) {}

    CyberInterposer::PFN_Table_NVNGX_Parameter_Union_P::PFN_Table_NVNGX_Parameter_Union_P() : param(nullptr) {};

    CI_MGX_Parameter_StaticAlloc CI_MGX_Parameter_StaticAlloc::GetParameters_depreciated = {};
    CI_MGX_Parameter_StaticAlloc CI_MGX_Parameter_StaticAlloc::AllocateParameters = {};

    CI_Parameter* CI_MGX_Parameter_StaticAlloc::claim() noexcept(false) {
        std::lock_guard<std::mutex> lock(allocatorMutex);

        for (std::size_t i = 0; i < PoolSize; ++i) {
            if (!freeSlots.test(i)) {
                freeSlots.set(i);
                return &memoryPool[i];
            }
        }

        throw std::runtime_error("No free slots available.");
    }

    CI_Parameter* CI_MGX_Parameter_StaticAlloc::claim(std::size_t number) noexcept(false) {
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

    bool CI_MGX_Parameter_StaticAlloc::release(CI_Parameter* p) noexcept(false) {
        std::lock_guard<std::mutex> lock(allocatorMutex);

        std::ptrdiff_t index = p - memoryPool.data();

        if (index < 0 || index >= static_cast<std::ptrdiff_t>(PoolSize) || !freeSlots.test(index)) {
            throw std::invalid_argument("Invalid pointer or not currently claimed.");
        }

        freeSlots.reset(index);
        return true;
    }

    bool CI_MGX_Parameter_StaticAlloc::release(CI_Parameter* p, std::size_t number) noexcept(false) {
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
}


NVSDK_NGX_Result C_Declare NVSDK_NGX_DLSS_GetOptimalSettingsCallback(CyberInterposer::CI_Parameter* InParams)
{
    return InParams->GetOptimalSettingsCallback(InParams);
}

NVSDK_NGX_Result C_Declare NVSDK_NGX_DLSS_GetStatsCallback(CyberInterposer::CI_Parameter* InParams)
{
    return InParams->GetStatsCallback(InParams);
}
