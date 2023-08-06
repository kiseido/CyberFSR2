#include "pch.h"
#include "CyberTypes.h"



constexpr std::wstring_view GET_PART_AFTER_PREFIX(const std::wstring_view& prefix, const std::wstring_view& name) {
    return name.substr(prefix.size());
}

constexpr bool CHECK_STARTS_WITH(const std::wstring_view& prefix, const std::wstring_view& name) {
    return name.compare(0, prefix.size(), prefix) == 0;
}

constexpr std::wstring_view TRY_REMOVE_PREFIX(const std::wstring_view& prefix, const std::wstring_view& name) {
    if (CHECK_STARTS_WITH(prefix, name)) {
        return GET_PART_AFTER_PREFIX(prefix, name);
    }
    else {
        return name;
    }
}

#define CyberEnumSwitchHelperOStream(stream, prefix, name) \
    case name: { \
        stream << TRY_REMOVE_PREFIX(L#prefix, L#name); \
        break;\
    }

#define CyberEnumSwitchHelperReturner(prefix, name) \
    case name: { \
        return TRY_REMOVE_PREFIX(L#prefix, L#name); \
    }

std::wstring CyberTypes::stringToWstring(const std::string& str) {
    if (str.empty())
        return std::wstring();

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::vector<wchar_t> wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
    return std::wstring(str.begin(), str.end());
}


CyberTypes::HighPerformanceCounterInfo::HighPerformanceCounterInfo() : frequency(), counter() {}

CyberTypes::HighPerformanceCounterInfo::HighPerformanceCounterInfo(const bool& performInitLogic) {
    if (performInitLogic) {
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&counter);
    }
    else {
        frequency = LARGE_INTEGER();
        counter = LARGE_INTEGER();
    }
}

CyberTypes::HighPerformanceCounterInfo::HighPerformanceCounterInfo(const HighPerformanceCounterInfo& other) : counter(other.counter), frequency(other.frequency)
{
}

CyberTypes::CoreInfo::CoreInfo() : logicalProcessorId(), processorTick() {}

CyberTypes::CoreInfo::CoreInfo(const bool& performInitLogic) {
    if (performInitLogic) {
        processorTick = __rdtsc();
        logicalProcessorId = GetCurrentProcessorNumber();
    }
    else {
        processorTick = 0;
        logicalProcessorId = 0;
    }
}

CyberTypes::CoreInfo::CoreInfo(const CoreInfo& other) : logicalProcessorId(other.logicalProcessorId), processorTick(other.processorTick) {}

CyberTypes::RTC::RTC() : timestamp() {}

CyberTypes::RTC::RTC(const bool& performInitLogic) {
    if (!performInitLogic) return;
    timestamp = std::chrono::system_clock::now();
}

CyberTypes::RTC::RTC(const RTC& other) : timestamp(other.timestamp) {}



CyberTypes::SystemInfo::SystemInfo() : coreInfo(), highPerformanceCounterInfo(), rtc()
{
}

CyberTypes::SystemInfo::SystemInfo(const bool& doCoreInfo, const bool& doPerformanceInfo, const bool& doRTC) : coreInfo(doCoreInfo), highPerformanceCounterInfo(doPerformanceInfo), rtc(doRTC), DoCoreInfo(doCoreInfo), DoPerformanceInfo(doPerformanceInfo), DoRTC(doRTC) {}

CyberTypes::SystemInfo::SystemInfo(const SystemInfo& other) : coreInfo(other.coreInfo), highPerformanceCounterInfo(other.highPerformanceCounterInfo), rtc(other.rtc), DoPerformanceInfo(other.DoPerformanceInfo), DoCoreInfo(other.DoCoreInfo), DoRTC(other.DoRTC) {}



CyberTypes::CyString to_CyString(const std::string_view& input) {
    return std::wstring(input.begin(), input.end());
}


std::wostream& operator<<(std::wostream& os, const std::string_view& view) {
    os << std::wstring(view.begin(), view.end());
    return os;
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CyString& view)
{
    os << (std::wstring)view;
    return os;
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CyString_view& view)
{
    os << (std::wstring_view)view;
    return os;
}




CyberTypes::CyString::CyString() : std::wstring() {}

CyberTypes::CyString::CyString(const CyString& other) : std::wstring(other){}

CyberTypes::CyString::CyString(const std::wstring& wstr) : std::wstring(wstr){}

CyberTypes::CyString::CyString(const std::wstring_view& wview) : CyString(to_CyString(wview)){}

CyberTypes::CyString::CyString(const std::string& str) : CyString(to_CyString(str)){}

CyberTypes::CyString::CyString(const std::string_view& view) : CyString(to_CyString(view)){}

CyberTypes::CyString::CyString(const char* cstr) : CyString(std::string_view(cstr)){}

CyberTypes::CyString::CyString(const wchar_t* wcstr) : CyString((std::wstring_view)wcstr){}

CyberTypes::CyString_view::CyString_view() : std::wstring_view(){}

CyberTypes::CyString_view::CyString_view(const CyString_view& other) : std::wstring_view(other){}

CyberTypes::CyString_view::CyString_view(const std::wstring& wstr) : std::wstring_view(wstr){}

CyberTypes::CyString_view::CyString_view(const std::wstring_view& wview) : std::wstring_view(wview){}

CyberTypes::CyString_view::CyString_view(const wchar_t* wcstr) : std::wstring_view(wcstr){}

CyberTypes::CyString to_CyString(const std::wstring& input) {
    return input;
}

CyberTypes::CyString to_CyString(const std::wstring_view& input) {
    return input.data();
}

CyberTypes::CyString to_CyString(const std::string& input) {
    return CyberTypes::stringToWstring(input);
}

//

std::wostream& operator<<(std::wostream& os, const CyberTypes::HighPerformanceCounterInfo& counterInfo) {
    os << "HPC: " << counterInfo.counter.QuadPart << " / " << counterInfo.frequency.QuadPart;
    return os;
}

CyberTypes::CyString to_CyString(const CyberTypes::HighPerformanceCounterInfo& input) {
    std::wostringstream os;
    os << "HPC: " << input.counter.QuadPart << " / " << input.frequency.QuadPart;
    return os.str();
}

//

std::wostream& operator<<(std::wostream& os, const CyberTypes::CoreInfo& coreInfo) {
    os << "Core: " << coreInfo.logicalProcessorId << " - " << "Tick: " << coreInfo.processorTick;
    return os;
}

CyberTypes::CyString to_CyString(const CyberTypes::CoreInfo& input) {
    std::wostringstream os;
    os << "Core: " << input.logicalProcessorId << " - " << "Tick: " << input.processorTick;
    return os.str();
}

//

std::wostream& operator<<(std::wostream& os, const CyberTypes::RTC& rtc) {
    os << "RTC: " << rtc.timestamp;
    return os;
}

CyberTypes::CyString to_CyString(const CyberTypes::RTC& input) {
    std::wostringstream os;
    os << "RTC: " << input.timestamp;
    return os.str();
}

//

std::wostream& operator<<(std::wostream& os, const CyberTypes::SystemInfo& systemInfo) {
    if (systemInfo.DoCoreInfo) {
        os << systemInfo.coreInfo;
        os << " -- ";
    }
    if (systemInfo.DoPerformanceInfo) {
        os << systemInfo.highPerformanceCounterInfo;
        os << " -- ";
    }
    if (systemInfo.DoRTC) {
        os << systemInfo.rtc;
    }
    return os;
}

CyberTypes::CyString to_CyString(const CyberTypes::SystemInfo& input) {
    std::wostringstream os;
    if (input.DoCoreInfo) {
        os << to_CyString(input.coreInfo);
        os << L" -- ";
    }
    if (input.DoPerformanceInfo) {
        os << to_CyString(input.highPerformanceCounterInfo);
        os << L" -- ";
    }
    if (input.DoRTC) {
        os << to_CyString(input.rtc);
    }
    return os.str();
}

//

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Version_t& version) {
    os << (DWORD)version;
    return os;
}


CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Version_t& input) {
    std::wostringstream os;
    os << (DWORD)input;
    return os.str();
}

//

// Convert CyberTypes::CT_NGX_Application_Identifier_Type_t to CyberTypes::CyString
CyberTypes::CyString_view to_CyString(const CyberTypes::CT_NGX_Application_Identifier_Type_t& input) {
    switch (input) {
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Application_Identifier_Type_, NVSDK_NGX_Application_Identifier_Type_Application_Id);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Application_Identifier_Type_, NVSDK_NGX_Application_Identifier_Type_Project_Id);
    default:
        return L"CI_Unknown";
    }
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Application_Identifier_Type_t& identifierType) {
    os << "NVSDK_NGX_Application_Identifier_Type: ";
    os << to_CyString(identifierType);
    return os;
}

//

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_ProjectIdDescription_t& desc) {
    os << "Project ID: " << desc.ProjectId << ", ";
    os << "Engine Type: " << desc.EngineType << ", ";
    os << "Engine Version: " << desc.EngineVersion;
    return os;
}

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_ProjectIdDescription_t& input) {
    std::wostringstream os;
    os << "Project ID: " << input.ProjectId << L", ";
    os << "Engine Type: " << input.EngineType << L", ";
    os << "Engine Version: " << input.EngineVersion;
    return os.str();
}

//

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Application_Identifier_t& identifier) {
    os << to_CyString(identifier);
    return os;
}

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Application_Identifier_t& identifier) {
    switch (identifier.IdentifierType) {
    case NVSDK_NGX_Application_Identifier_Type_Application_Id:
        return std::to_wstring(identifier.v.ApplicationId);
    case NVSDK_NGX_Application_Identifier_Type_Project_Id:
        return to_CyString(identifier.v.ProjectDesc);
    default:
        return L"CI_Unknown";
    }
}

//

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Result_t& result) {
    return CyberTypes::CyString(std::to_wstring(result));
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Result_t& result) {
    os << to_CyString(result);
    return os;
}

//

CyberTypes::CyString_view to_CyString(const CyberTypes::CT_NGX_Buffer_Format_t& bufferFormat) {
    switch (bufferFormat) {
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_Unknown);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_RGB8UI);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_RGB16F);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_RGB32F);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_RGBA8UI);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_RGBA16F);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_RGBA32F);
    default:
        return L"CI_Unknown";
    }
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Buffer_Format_t& bufferFormat) {
    os << to_CyString(bufferFormat);
    return os;
}

//

CyberTypes::CyString_view to_CyString(const CyberTypes::CT_NGX_ToneMapperType_t& toneMapperType) {
    switch (toneMapperType) {
        CyberEnumSwitchHelperReturner(NVSDK_NGX_TONEMAPPER_, NVSDK_NGX_TONEMAPPER_STRING);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_TONEMAPPER_, NVSDK_NGX_TONEMAPPER_REINHARD);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_TONEMAPPER_, NVSDK_NGX_TONEMAPPER_ONEOVERLUMA);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_TONEMAPPER_, NVSDK_NGX_TONEMAPPER_ACES);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_TONEMAPPER_, NVSDK_NGX_TONEMAPPERTYPE_NUM);
    default: 
        return L"CI_Unknown";
    }
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_ToneMapperType_t& toneMapperType) {
    os << to_CyString(toneMapperType);
    return os;
}

//

CyberTypes::CyString_view to_CyString(const CyberTypes::CT_NGX_GBufferType_t& gBufferType) {
    switch (gBufferType) {
    CyberEnumSwitchHelperReturner(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_ALBEDO);
    CyberEnumSwitchHelperReturner(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_ROUGHNESS);
    CyberEnumSwitchHelperReturner(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_METALLIC);
    CyberEnumSwitchHelperReturner(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_SPECULAR);
    CyberEnumSwitchHelperReturner(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_NORMALS);
    CyberEnumSwitchHelperReturner(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_SHADINGMODELID);
    CyberEnumSwitchHelperReturner(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_MATERIALID);
    CyberEnumSwitchHelperReturner(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_SPECULAR_ALBEDO);
    CyberEnumSwitchHelperReturner(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_INDIRECT_ALBEDO);
    CyberEnumSwitchHelperReturner(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_SPECULAR_MVEC);
    CyberEnumSwitchHelperReturner(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_DISOCCL_MASK);
    CyberEnumSwitchHelperReturner(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_EMISSIVE);
    CyberEnumSwitchHelperReturner(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFERTYPE_NUM);
    default:
        return L"CI_Unknown";
    }
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_GBufferType_t& gBufferType) {
    os << to_CyString(gBufferType);
    return os;
}

//

CyberTypes::CyString_view to_CyString(const CyberTypes::CT_NGX_Feature_t& input) {
    switch (input) {
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Feature_, NVSDK_NGX_Feature_Reserved0);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Feature_, NVSDK_NGX_Feature_SuperSampling);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Feature_, NVSDK_NGX_Feature_InPainting);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Feature_, NVSDK_NGX_Feature_ImageSuperResolution);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Feature_, NVSDK_NGX_Feature_SlowMotion);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Feature_, NVSDK_NGX_Feature_VideoSuperResolution);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Feature_, NVSDK_NGX_Feature_Reserved1);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Feature_, NVSDK_NGX_Feature_Reserved2);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Feature_, NVSDK_NGX_Feature_Reserved3);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Feature_, NVSDK_NGX_Feature_ImageSignalProcessing);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Feature_, NVSDK_NGX_Feature_DeepResolve);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Feature_, NVSDK_NGX_Feature_DeepDVC);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Feature_, NVSDK_NGX_Feature_Reserved13);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Feature_, NVSDK_NGX_Feature_Count);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Feature_, NVSDK_NGX_Feature_Reserved_SDK);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Feature_, NVSDK_NGX_Feature_Reserved_Core);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_Feature_, NVSDK_NGX_Feature_Reserved_Unknown);
    default:
        return L"CI_Unknown";
    }
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Feature_t& input) {
    os << to_CyString(input);
    return os;
}

// CT_NGX_Coordinates_t

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Coordinates_t& coordinates) {
    return L"(" + std::to_wstring(coordinates.X) + L", " + std::to_wstring(coordinates.Y) + L")";
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Coordinates_t& coordinates) {
    os << to_CyString(coordinates);
    return os;
}

// CT_NGX_Dimensions_t

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Dimensions_t& dimensions) {
    return L"[" + std::to_wstring(dimensions.Width) + L"x" + std::to_wstring(dimensions.Height) + L"]";
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Dimensions_t& dimensions) {
    os << to_CyString(dimensions);
    return os;
}

// CT_NGX_PathListInfo_t

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_PathListInfo_t& pathListInfo) {
    CyberTypes::CyString result = L"[";
    for (unsigned int i = 0; i < pathListInfo.Length; ++i) {
        result += pathListInfo.Path[i];
        if (i < pathListInfo.Length - 1) {
            result += L", ";
        }
    }
    result += L"]";
    return result;
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_PathListInfo_t& pathListInfo) {
    os << to_CyString(pathListInfo);
    return os;
}

// CT_NGX_Logging_Level_t

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Logging_Level_t& loggingLevel) {
    switch (loggingLevel) {
        CyberEnumSwitchHelperReturner(NVSDK_NGX_LOGGING_LEVEL_, NVSDK_NGX_LOGGING_LEVEL_OFF);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_LOGGING_LEVEL_, NVSDK_NGX_LOGGING_LEVEL_ON);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_LOGGING_LEVEL_, NVSDK_NGX_LOGGING_LEVEL_VERBOSE);
    default:
        return L"CI_Unknown";
    }
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Logging_Level_t& loggingLevel) {
    os << to_CyString(loggingLevel);
    return os;
}

// CT_NGX_Resource_VK_Type_t

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Resource_VK_Type_t& resourceVKType) {
    switch (resourceVKType) {
        CyberEnumSwitchHelperReturner(NVSDK_NGX_RESOURCE_VK_TYPE_, NVSDK_NGX_RESOURCE_VK_TYPE_VK_IMAGEVIEW);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_RESOURCE_VK_TYPE_, NVSDK_NGX_RESOURCE_VK_TYPE_VK_BUFFER);
    default:
        return L"CI_Unknown";
    }
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Resource_VK_Type_t& resourceVKType) {
    os << to_CyString(resourceVKType);
    return os;
}

// CT_NGX_Opt_Level_t

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Opt_Level_t& optLevel) {
    switch (optLevel) {
        CyberEnumSwitchHelperReturner(NVSDK_NGX_OPT_LEVEL_, NVSDK_NGX_OPT_LEVEL_UNDEFINED);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_OPT_LEVEL_, NVSDK_NGX_OPT_LEVEL_DEBUG);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_OPT_LEVEL_, NVSDK_NGX_OPT_LEVEL_DEVELOP);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_OPT_LEVEL_, NVSDK_NGX_OPT_LEVEL_RELEASE);
    default:
        return L"CI_Unknown";
    }
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Opt_Level_t& optLevel) {
    os << to_CyString(optLevel);
    return os;
}


// CT_NGX_EngineType_t

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_EngineType_t& engineType) {
    switch (engineType) {
        CyberEnumSwitchHelperReturner(NVSDK_NGX_ENGINE_TYPE_, NVSDK_NGX_ENGINE_TYPE_CUSTOM);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_ENGINE_TYPE_, NVSDK_NGX_ENGINE_TYPE_UNREAL);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_ENGINE_TYPE_, NVSDK_NGX_ENGINE_TYPE_UNITY);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_ENGINE_TYPE_, NVSDK_NGX_ENGINE_TYPE_OMNIVERSE);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_ENGINE_TYPE_, NVSDK_NGX_ENGINE_COUNT);
    default:
        return L"CI_Unknown";
    }
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_EngineType_t& engineType) {
    os << to_CyString(engineType);
    return os;
}

// CT_NGX_Feature_Support_Result_t

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Feature_Support_Result_t& featureSupportResult) {
    switch (featureSupportResult) {
        CyberEnumSwitchHelperReturner(NVSDK_NGX_FeatureSupportResult_, NVSDK_NGX_FeatureSupportResult_Supported);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_FeatureSupportResult_, NVSDK_NGX_FeatureSupportResult_CheckNotPresent);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_FeatureSupportResult_, NVSDK_NGX_FeatureSupportResult_DriverVersionUnsupported);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_FeatureSupportResult_, NVSDK_NGX_FeatureSupportResult_AdapterUnsupported);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_FeatureSupportResult_, NVSDK_NGX_FeatureSupportResult_OSVersionBelowMinimumSupported);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_FeatureSupportResult_, NVSDK_NGX_FeatureSupportResult_NotImplemented);
    default:
        return L"CI_Unknown";
    }
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Feature_Support_Result_t& featureSupportResult) {
    os << to_CyString(featureSupportResult);
    return os;
}

// CT_AppId_t

CyberTypes::CyString to_CyString(const CyberTypes::CT_AppId_t& appId) {
    return CyberTypes::CyString(std::to_wstring((unsigned long long) appId));
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_AppId_t& appId) {
    os << to_CyString(appId);
    return os;
}

// CT_NVSDK_NGX_GPU_Arch_t

CyberTypes::CyString to_CyString(const CyberTypes::CT_NVSDK_NGX_GPU_Arch_t& gpuArch) {
    switch (gpuArch) {
        CyberEnumSwitchHelperReturner(NVSDK_NGX_GPU_Arch_, NVSDK_NGX_GPU_Arch_NotSupported);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_GPU_Arch_, NVSDK_NGX_GPU_Arch_Volta);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_GPU_Arch_, NVSDK_NGX_GPU_Arch_Turing);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_GPU_Arch_, NVSDK_NGX_GPU_Arch_Unknown);
    default:
        return L"CI_Unknown";
    }
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_GPU_Arch_t& gpuArch) {
    os << to_CyString(gpuArch);
    return os;
}

// CT_NGX_DLSS_Hint_Render_Preset_t

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_DLSS_Hint_Render_Preset_t& renderPreset) {
    switch (renderPreset) {
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_Hint_Render_Preset_, NVSDK_NGX_DLSS_Hint_Render_Preset_Default);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_Hint_Render_Preset_, NVSDK_NGX_DLSS_Hint_Render_Preset_A);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_Hint_Render_Preset_, NVSDK_NGX_DLSS_Hint_Render_Preset_B);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_Hint_Render_Preset_, NVSDK_NGX_DLSS_Hint_Render_Preset_C);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_Hint_Render_Preset_, NVSDK_NGX_DLSS_Hint_Render_Preset_D);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_Hint_Render_Preset_, NVSDK_NGX_DLSS_Hint_Render_Preset_E);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_Hint_Render_Preset_, NVSDK_NGX_DLSS_Hint_Render_Preset_F);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_Hint_Render_Preset_, NVSDK_NGX_DLSS_Hint_Render_Preset_G);
    default:
        return L"CI_Unknown";
    }
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_DLSS_Hint_Render_Preset_t& renderPreset) {
    os << to_CyString(renderPreset);
    return os;
}


// CT_NGX_DLSS_Mode_t
CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_DLSS_Mode_t& dlssMode) {
    switch (dlssMode) {
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_Mode_, NVSDK_NGX_DLSS_Mode_Off);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_Mode_, NVSDK_NGX_DLSS_Mode_DLSS_DLISP);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_Mode_, NVSDK_NGX_DLSS_Mode_DLISP_Only);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_Mode_, NVSDK_NGX_DLSS_Mode_DLSS);
    default:
        return L"CI_Unknown";
    }
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_DLSS_Mode_t& dlssMode) {
    os << to_CyString(dlssMode);
    return os;
}

// CT_NGX_DeepDVC_Mode_t
CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_DeepDVC_Mode_t& deepDVCMode) {
    switch (deepDVCMode) {
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_DeepDVC_Mode_, NVSDK_NGX_DLSS_DeepDVC_Mode_Off);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_DeepDVC_Mode_, NVSDK_NGX_DLSS_DeepDVC_Mode_On);
    default:
        return L"CI_Unknown";
    }
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_DeepDVC_Mode_t& deepDVCMode) {
    os << to_CyString(deepDVCMode);
    return os;
}

// CT_NGX_FeatureCommonInfo_Internal_t

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_FeatureCommonInfo_Internal_t& featureCommonInfo) {
    // Placeholder. Adjust based on the actual members of the struct.
    return L"FeatureCommonInfo_Internal";
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_FeatureCommonInfo_Internal_t& featureCommonInfo) {
    os << to_CyString(featureCommonInfo);
    return os;
}

// CT_NGX_DLSS_Feature_Flags_t

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_DLSS_Feature_Flags_t& dlssFeatureFlags) {
    switch (dlssFeatureFlags) {
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_DeepDVC_Mode_, NVSDK_NGX_DLSS_Feature_Flags_IsInvalid);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_DeepDVC_Mode_, NVSDK_NGX_DLSS_Feature_Flags_None);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_DeepDVC_Mode_, NVSDK_NGX_DLSS_Feature_Flags_IsHDR);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_DeepDVC_Mode_, NVSDK_NGX_DLSS_Feature_Flags_MVLowRes);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_DeepDVC_Mode_, NVSDK_NGX_DLSS_Feature_Flags_MVJittered);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_DeepDVC_Mode_, NVSDK_NGX_DLSS_Feature_Flags_DepthInverted);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_DeepDVC_Mode_, NVSDK_NGX_DLSS_Feature_Flags_Reserved_0);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_DeepDVC_Mode_, NVSDK_NGX_DLSS_Feature_Flags_DoSharpening);
        CyberEnumSwitchHelperReturner(NVSDK_NGX_DLSS_DeepDVC_Mode_, NVSDK_NGX_DLSS_Feature_Flags_AutoExposure);
    default:
        return L"CI_Unknown";
    }
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_DLSS_Feature_Flags_t& dlssFeatureFlags) {
    os << to_CyString(dlssFeatureFlags);
    return os;
}

// CT_NGX_Handle_t
CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Handle_t& ngxHandle) {
    return std::to_wstring(ngxHandle.Id);
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Handle_t& ngxHandle) {
    os << to_CyString(ngxHandle);
    return os;
}

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_FeatureRequirement_t& featureRequirement) {
    CyberTypes::CyString result;

    result += L"Feature Supported: ";
    switch (featureRequirement.FeatureSupported) {
    case NVSDK_NGX_FeatureSupportResult_Supported:
        result += L"Supported";
        break;
    case NVSDK_NGX_FeatureSupportResult_CheckNotPresent:
        result += L"CheckNotPresent";
        break;
    case NVSDK_NGX_FeatureSupportResult_DriverVersionUnsupported:
        result += L"DriverVersionUnsupported";
        break;
    case NVSDK_NGX_FeatureSupportResult_AdapterUnsupported:
        result += L"AdapterUnsupported";
        break;
    case NVSDK_NGX_FeatureSupportResult_OSVersionBelowMinimumSupported:
        result += L"OSVersionBelowMinimumSupported";
        break;
    case NVSDK_NGX_FeatureSupportResult_NotImplemented:
        result += L"NotImplemented";
        break;
    default:
        result += L"Unknown";
        break;
    }

    // Add a separator (e.g., a comma) between members or use any other appropriate format.
    result += L", ";

    // Convert the MinHWArchitecture to a string.
    result += L"Minimum HW Architecture: " + std::to_wstring(featureRequirement.MinHWArchitecture);

    // Add another separator.
    result += L", ";

    // Convert the MinOSVersion to a string.
    result += L"Minimum OS Version: " + to_CyString(std::string_view(featureRequirement.MinOSVersion));

    return result;
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_FeatureRequirement_t& featureRequirement) {
    os << to_CyString(featureRequirement);
    return os;
}