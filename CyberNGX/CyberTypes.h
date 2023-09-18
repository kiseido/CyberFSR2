#include "pch.h"

#ifndef CyberTypes_H
#define CyberTypes_H

#include <map>
#include <string_view>
#include <format>

#include <nvsdk_ngx.h>
#include <nvsdk_ngx_defs.h>

#include "Utils.h"

namespace CyberTypes {

    struct Resolution_Dimensions {
        constexpr static double initialValue = -std::numeric_limits<double>::infinity();
        double width = initialValue;
        double height = initialValue;
    };

// #define WrapIt(BaseType) typedef Wrapper<BaseType> CT_##BaseType##_t; typedef union {BaseType base; CT_##BaseType##_t wrapped;} CT_##BaseType##_u; std::wostream& CyberTypes::CT_##BaseType##_u::operator<<(std::wostream& wos)

#define WrapIt(BaseType) typedef CyberUtils::UnionWrapper<BaseType> CT_##BaseType##_u; std::wostream& operator<<(std::wostream& wos, const CT_##BaseType##_u&)

    struct NVSDK_NGX_FeatureCommonInfo_Internal  {};

    // Define wrapper classes for specific types
    WrapIt(AppId);

    WrapIt(NVSDK_NGX_GPU_Arch);
    WrapIt(NVSDK_NGX_DLSS_Hint_Render_Preset);
    WrapIt(NVSDK_NGX_FeatureCommonInfo_Internal);
    WrapIt(NVSDK_NGX_Version);
    WrapIt(NVSDK_NGX_Result);
    WrapIt(NVSDK_NGX_Feature);
    WrapIt(NVSDK_NGX_Buffer_Format);
    WrapIt(NVSDK_NGX_PerfQuality_Value);
    WrapIt(NVSDK_NGX_RTX_Value);
    WrapIt(NVSDK_NGX_DLSS_Mode);
    WrapIt(NVSDK_NGX_DeepDVC_Mode);
    WrapIt(NVSDK_NGX_Handle);
    WrapIt(NVSDK_NGX_DLSS_Feature_Flags);
    WrapIt(NVSDK_NGX_ToneMapperType);
    WrapIt(NVSDK_NGX_GBufferType);
    WrapIt(NVSDK_NGX_Coordinates);
    WrapIt(NVSDK_NGX_Dimensions);
    WrapIt(NVSDK_NGX_PathListInfo);
    WrapIt(NVSDK_NGX_Logging_Level);
    WrapIt(NVSDK_NGX_FeatureCommonInfo);
    WrapIt(NVSDK_NGX_Resource_VK_Type);
    WrapIt(NVSDK_NGX_Opt_Level);
    WrapIt(NVSDK_NGX_EngineType);
    WrapIt(NVSDK_NGX_Feature_Support_Result);
    WrapIt(NVSDK_NGX_Application_Identifier_Type);
    WrapIt(NVSDK_NGX_ProjectIdDescription);
    WrapIt(NVSDK_NGX_Application_Identifier);
    WrapIt(NVSDK_NGX_FeatureDiscoveryInfo);
    WrapIt(NVSDK_NGX_FeatureRequirement);

#undef WrapIt

    class CyString : public std::wstring {
    public:
        CyString();
        CyString(const std::wstring& wstr);
        CyString(const std::wstring_view& wview);
        CyString(const std::string& str);
        CyString(const std::string_view& view);
        CyString(const CyString& other);
        CyString(const char* cstr);
        CyString(const wchar_t* wcstr);

        friend CyString operator"" _CyStrView(const char* str, size_t len) {
            return CyString(std::string_view(str, len));
        }
    };

    class CyString_view : public std::wstring_view {
    public:
        CyString_view();
        CyString_view(const std::wstring& wstr);
        CyString_view(const std::wstring_view& wview);
        CyString_view(const wchar_t* wcstr);
        CyString_view(const CyString_view& other);

        friend CyString_view operator"" _CyWStrView(const wchar_t* str, size_t len) {
            return std::wstring_view(str, len);
        }
    };

    struct HighPerformanceCounterInfo {
        LARGE_INTEGER frequency;
        LARGE_INTEGER counter;

        HighPerformanceCounterInfo();
        HighPerformanceCounterInfo(const bool& performInitLogic);
        HighPerformanceCounterInfo(const HighPerformanceCounterInfo& other);
    };

    struct CoreInfo {
        int logicalProcessorId;
        long long processorTick;

        CoreInfo();
        CoreInfo(const bool& performInitLogic);
        CoreInfo(const CoreInfo& other);
    };

    struct RTC {
        std::chrono::system_clock::time_point timestamp;

        RTC();
        RTC(const bool& performInitLogic);
        RTC(const RTC& other);
    };

    struct SystemInfo {
        CoreInfo coreInfo;
        HighPerformanceCounterInfo highPerformanceCounterInfo;
        RTC rtc;

        bool DoPerformanceInfo = true;
        bool DoCoreInfo = true;
        bool DoRTC = true;

        SystemInfo();
        SystemInfo(const bool& doCoreInfo, const bool& doPerformanceInfo, const bool& doRTC);
        SystemInfo(const SystemInfo& other);
    };

    std::wstring stringToWstring(const std::string& str);


}

std::wostream& operator<<(std::wostream& os, const CyberTypes::SystemInfo& systemInfo);
std::wostream& operator<<(std::wostream& os, const CyberTypes::RTC& rtc);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CoreInfo& coreInfo);
std::wostream& operator<<(std::wostream& os, const CyberTypes::HighPerformanceCounterInfo& counterInfo);

template <typename T1, typename T2>
void stringify_args_helper(T1& os, const T2& str) {
    os << str << L" ";
}

template <typename T1>
void stringify_args_helper(T1& os, const char str[]) {
    os << CyberTypes::stringToWstring(str) << L" ";
}

template <typename T1>
void stringify_args_helper(T1& os, const wchar_t str[]) {
    os << str << L" ";
}

template <typename... Args>
std::wstring stringify_args(const Args&... args) {
    std::wostringstream ss;
    (stringify_args_helper(ss, args), ...);
    return ss.str();
}

#endif