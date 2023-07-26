#include "pch.h"

#ifndef CyberTypes_H
#define CyberTypes_H

#include <map>
#include <string_view>

#include <nvsdk_ngx.h>
#include <nvsdk_ngx_defs.h>

namespace CyberTypes {

    typedef AppId                                   CT_AppId_t;

    typedef NVSDK_NGX_GPU_Arch                      CT_NVSDK_NGX_GPU_Arch_t;

    typedef NVSDK_NGX_DLSS_Hint_Render_Preset       CT_NGX_DLSS_Hint_Render_Preset_t;
    typedef NVSDK_NGX_FeatureCommonInfo_Internal    CT_NGX_FeatureCommonInfo_Internal_t;
    typedef NVSDK_NGX_Version                       CT_NGX_Version_t;
    typedef NVSDK_NGX_Result                        CT_NGX_Result_t;
    typedef NVSDK_NGX_Feature                       CT_NGX_Feature_t;
    typedef NVSDK_NGX_Buffer_Format                 CT_NGX_Buffer_Format_t;
    typedef NVSDK_NGX_PerfQuality_Value             CT_NGX_PerfQuality_Value_t;
    typedef NVSDK_NGX_RTX_Value                     CT_NGX_RTX_Value_t;
    typedef NVSDK_NGX_DLSS_Mode                     CT_NGX_DLSS_Mode_t;
    typedef NVSDK_NGX_DeepDVC_Mode                  CT_NGX_DeepDVC_Mode_t;
    typedef NVSDK_NGX_Handle                        CT_NGX_Handle_t;
    typedef NVSDK_NGX_DLSS_Feature_Flags            CT_NGX_DLSS_Feature_Flags_t;
    typedef NVSDK_NGX_ToneMapperType                CT_NGX_ToneMapperType_t;
    typedef NVSDK_NGX_GBufferType                   CT_NGX_GBufferType_t;
    typedef NVSDK_NGX_Coordinates                   CT_NGX_Coordinates_t;
    typedef NVSDK_NGX_Dimensions                    CT_NGX_Dimensions_t;
    typedef NVSDK_NGX_PathListInfo                  CT_NGX_PathListInfo_t;
    typedef NVSDK_NGX_Logging_Level                 CT_NGX_Logging_Level_t;
    typedef NVSDK_NGX_FeatureCommonInfo             CT_NGX_FeatureCommonInfo_t;
    typedef NVSDK_NGX_Resource_VK_Type              CT_NGX_Resource_VK_Type_t;
    typedef NVSDK_NGX_Opt_Level                     CT_NGX_Opt_Level_t;
    typedef NVSDK_NGX_EngineType                    CT_NGX_EngineType_t;
    typedef NVSDK_NGX_Feature_Support_Result        CT_NGX_Feature_Support_Result_t;
    typedef NVSDK_NGX_Application_Identifier_Type   CT_NGX_Application_Identifier_Type_t;
    typedef NVSDK_NGX_ProjectIdDescription          CT_NGX_ProjectIdDescription_t;
    typedef NVSDK_NGX_Application_Identifier        CT_NGX_Application_Identifier_t;
    typedef NVSDK_NGX_FeatureDiscoveryInfo          CT_NGX_FeatureDiscoveryInfo_t;
    typedef NVSDK_NGX_FeatureRequirement            CT_NGX_FeatureRequirement_t;


    class CyString : public std::wstring {
    public:
        CyString();
        CyString(const std::wstring& wstr);
        CyString(const std::wstring_view& wview);
        CyString(const std::string& str);
        CyString(const std::string_view& view);
        CyString(const char* cstr);
        CyString(const wchar_t* wcstr);
        CyString(const CyString& other);
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

    template<typename T1>
    T1& variadicLogHelper(T1& os) {
        return os;
    }

    template<typename T1, typename T2>
    T1& variadicLogHelper(T1& os, const T2& str) {
        os << str;
        return os;
    }

    template<typename T1, typename T2, typename... Args>
    T1& variadicLogHelper(T1& os, const T2& str, Args&&... args) {
        os << str;
        variadicLogHelper(os, std::forward<Args>(args)...);
        return os;
    }

    template<typename... Args>
    CyString convertToString(Args&&... args) {
        std::wostringstream  ss;
        variadicLogHelper(ss, std::forward<Args>(args)...);
        return ss.str();
    };

    std::wstring stringToWstring(const std::string& str);
}

CyberTypes::CyString to_CyString(const std::wstring&);

CyberTypes::CyString to_CyString(const std::wstring_view&);

CyberTypes::CyString to_CyString(const std::string&);

CyberTypes::CyString to_CyString(const std::string_view&);

CyberTypes::CyString to_CyString(const CyberTypes::HighPerformanceCounterInfo&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::HighPerformanceCounterInfo& counterInfo);

CyberTypes::CyString to_CyString(const CyberTypes::CoreInfo&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CoreInfo& coreInfo);

CyberTypes::CyString to_CyString(const CyberTypes::RTC&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::RTC& rtc);

CyberTypes::CyString to_CyString(const CyberTypes::SystemInfo&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::SystemInfo& systemInfo);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Result_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Result_t& result);

CyberTypes::CyString_view to_CyString(const CyberTypes::CT_NGX_Buffer_Format_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Buffer_Format_t& bufferFormat);

CyberTypes::CyString_view to_CyString(const CyberTypes::CT_NGX_ToneMapperType_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_ToneMapperType_t& toneMapperType);

CyberTypes::CyString_view to_CyString(const CyberTypes::CT_NGX_GBufferType_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_GBufferType_t& gBufferType);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Coordinates_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Coordinates_t& coordinates);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Dimensions_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Dimensions_t& dimensions);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_PathListInfo_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_PathListInfo_t& pathListInfo);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Logging_Level_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Logging_Level_t& loggingLevel);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Resource_VK_Type_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Resource_VK_Type_t& resourceVKType);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Opt_Level_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Opt_Level_t& optLevel);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_EngineType_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_EngineType_t& engineType);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Feature_Support_Result_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Feature_Support_Result_t& featureSupportResult);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_FeatureRequirement_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_FeatureRequirement_t& featureRequirement);

CyberTypes::CyString to_CyString(const CyberTypes::CT_AppId_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_AppId_t& appId);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NVSDK_NGX_GPU_Arch_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_GPU_Arch_t& gpuArch);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_DLSS_Hint_Render_Preset_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_DLSS_Hint_Render_Preset_t& renderPreset);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_DLSS_Mode_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_DLSS_Mode_t& dlssMode);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_DeepDVC_Mode_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_DeepDVC_Mode_t& deepDVCMode);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_FeatureCommonInfo_Internal_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_FeatureCommonInfo_Internal_t& featureCommonInfo);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_DLSS_Feature_Flags_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_DLSS_Feature_Flags_t& dlssFeatureFlags);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Handle_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Handle_t& ngxHandle);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Version_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Version_t& version);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_ProjectIdDescription_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_ProjectIdDescription_t& desc);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Application_Identifier_Type_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Application_Identifier_Type_t& identifierType);

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Application_Identifier_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Application_Identifier_t& identifier);

CyberTypes::CyString_view to_CyString(const CyberTypes::CT_NGX_Feature_t&);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Feature_t& feature);

std::wostream& operator<<(std::wostream& os, const CyberTypes::CyString& view);

std::wostream& operator<<(std::wostream& os, const CyberTypes::CyString_view& view);

#endif