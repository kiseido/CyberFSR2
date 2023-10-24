#pragma once

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

#define WrapThisTypeAndOperator(BaseType) typedef CyberUtils::UnionWrapper<BaseType> CT_##BaseType##_u; std::wostream& operator<<(std::wostream& wos, const CT_##BaseType##_u&)

    struct NVSDK_NGX_FeatureCommonInfo_Internal  {};

    // Define wrapper classes for specific types
    WrapThisTypeAndOperator(AppId);

    WrapThisTypeAndOperator(NVSDK_NGX_GPU_Arch);
    WrapThisTypeAndOperator(NVSDK_NGX_DLSS_Hint_Render_Preset);
    WrapThisTypeAndOperator(NVSDK_NGX_FeatureCommonInfo_Internal);
    WrapThisTypeAndOperator(NVSDK_NGX_Version);
    WrapThisTypeAndOperator(NVSDK_NGX_Result);
    WrapThisTypeAndOperator(NVSDK_NGX_Feature);
    WrapThisTypeAndOperator(NVSDK_NGX_Buffer_Format);
    WrapThisTypeAndOperator(NVSDK_NGX_PerfQuality_Value);
    WrapThisTypeAndOperator(NVSDK_NGX_RTX_Value);
    WrapThisTypeAndOperator(NVSDK_NGX_DLSS_Mode);
    WrapThisTypeAndOperator(NVSDK_NGX_DeepDVC_Mode);
    WrapThisTypeAndOperator(NVSDK_NGX_Handle);
    WrapThisTypeAndOperator(NVSDK_NGX_DLSS_Feature_Flags);
    WrapThisTypeAndOperator(NVSDK_NGX_ToneMapperType);
    WrapThisTypeAndOperator(NVSDK_NGX_GBufferType);
    WrapThisTypeAndOperator(NVSDK_NGX_Coordinates);
    WrapThisTypeAndOperator(NVSDK_NGX_Dimensions);
    WrapThisTypeAndOperator(NVSDK_NGX_PathListInfo);
    WrapThisTypeAndOperator(NVSDK_NGX_Logging_Level);
    WrapThisTypeAndOperator(NVSDK_NGX_FeatureCommonInfo);
    WrapThisTypeAndOperator(NVSDK_NGX_Resource_VK_Type);
    WrapThisTypeAndOperator(NVSDK_NGX_Opt_Level);
    WrapThisTypeAndOperator(NVSDK_NGX_EngineType);
    WrapThisTypeAndOperator(NVSDK_NGX_Feature_Support_Result);
    WrapThisTypeAndOperator(NVSDK_NGX_Application_Identifier_Type);
    WrapThisTypeAndOperator(NVSDK_NGX_ProjectIdDescription);
    WrapThisTypeAndOperator(NVSDK_NGX_Application_Identifier);
    WrapThisTypeAndOperator(NVSDK_NGX_FeatureDiscoveryInfo);
    WrapThisTypeAndOperator(NVSDK_NGX_FeatureRequirement);

#undef WrapThisTypeAndOperator

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
    };

    class CyString_view : public std::wstring_view {
    public:
        CyString_view();
        CyString_view(const std::wstring& wstr);
        CyString_view(const std::wstring_view& wview);
        CyString_view(const wchar_t* wcstr);
        CyString_view(const CyString_view& other);
    };

    struct HighPerformanceCounterInfo {
        long long frequency;
        long long counter;

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

    struct DLSS_Features {
        NVSDK_NGX_DLSS_Feature_Flags flags;

        bool IsHDR();
        bool IsMVLowRes();
        bool IsMVJittered();
        bool IsDepthInverted();
        bool IsDoSharpening();
        bool IsAutoExposure();
        bool IsReserved0();

        DLSS_Features& operator=(const NVSDK_NGX_DLSS_Feature_Flags& other);
        operator NVSDK_NGX_DLSS_Feature_Flags() const;
    };

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