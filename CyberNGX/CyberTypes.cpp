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

#define CyberEnumSwitchHelper(prefix, name) \
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

CyberTypes::CyString_view to_CyString(const CyberTypes::CT_NGX_Feature_t& input){
    switch (input) {

    case NVSDK_NGX_Feature_Reserved0:
        return L"Reserved0";

    case NVSDK_NGX_Feature_SuperSampling:
        return L"SuperSampling";

    case NVSDK_NGX_Feature_InPainting:
        return L"InPainting";

    case NVSDK_NGX_Feature_ImageSuperResolution:
        return L"ImageSuperResolution";

    case NVSDK_NGX_Feature_SlowMotion:
        return L"SlowMotion";

    case NVSDK_NGX_Feature_VideoSuperResolution:
        return L"VideoSuperResolution";

    case NVSDK_NGX_Feature_Reserved1:
        return L"Reserved1";

    case NVSDK_NGX_Feature_Reserved2:
        return L"Reserved2";

    case NVSDK_NGX_Feature_Reserved3:
        return L"Reserved3";

    case NVSDK_NGX_Feature_ImageSignalProcessing:
        return L"ImageSignalProcessing";

    case NVSDK_NGX_Feature_DeepResolve:
        return L"DeepResolve";

    case NVSDK_NGX_Feature_FrameGeneration:
        return L"FrameGeneration";

    case NVSDK_NGX_Feature_DeepDVC:
        return L"DeepDVC";

    case NVSDK_NGX_Feature_Reserved13:
        return L"Reserved13";

    case NVSDK_NGX_Feature_Count:
        return L"Count";

    case NVSDK_NGX_Feature_Reserved_SDK:
        return L"Reserved_SDK";

    case NVSDK_NGX_Feature_Reserved_Core:
        return L"Reserved_Core";

    case NVSDK_NGX_Feature_Reserved_Unknown:
        return L"Reserved_Unknown";
    }

    return L"Unknown_Feature";
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

std::wostream& operator<<(std::wostream& os, const CyberTypes::HighPerformanceCounterInfo& counterInfo) {
    os << "HPC: " << counterInfo.counter.QuadPart << " / " << counterInfo.frequency.QuadPart;
    return os;
}
std::wostream& operator<<(std::wostream& os, const CyberTypes::CoreInfo& coreInfo) {
    os << "Core: " << coreInfo.logicalProcessorId << " - " << "Tick: " << coreInfo.processorTick;
    return os;
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::RTC& rtc) {
    os << "RTC: " << rtc.timestamp;
    return os;
}

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

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Version_t& version) {
    os << (DWORD)version;
    return os;
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_ProjectIdDescription_t& desc) {
    os << "Project ID: " << desc.ProjectId << ", ";
    os << "Engine Type: " << desc.EngineType << ", ";
    os << "Engine Version: " << desc.EngineVersion;
    return os;
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Application_Identifier_Type_t& identifierType) {
    os << "NVSDK_NGX_Application_Identifier_Type: ";
    switch (identifierType) {
    case NVSDK_NGX_Application_Identifier_Type_Application_Id:
        os << "Application_Id";
        break;
    case NVSDK_NGX_Application_Identifier_Type_Project_Id:
        os << "Project_Id";
        break;
    }
    return os;
}


std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Feature_t& feature)
{
    os << to_CyString(feature);
    return os;
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Application_Identifier_t& identifier) {
    os << to_CyString(identifier);
    return os;
}

CyberTypes::CyString::CyString()
{
}

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

// Convert std::wstring to CyberTypes::CyString
CyberTypes::CyString to_CyString(const std::wstring& input) {
    return input;
}

// Convert std::wstring_view to CyberTypes::CyString
CyberTypes::CyString to_CyString(const std::wstring_view& input) {
    return input.data();
}

// Convert std::string to CyberTypes::CyString
CyberTypes::CyString to_CyString(const std::string& input) {
    return CyberTypes::stringToWstring(input);
}

// Convert CyberTypes::HighPerformanceCounterInfo to CyberTypes::CyString
CyberTypes::CyString to_CyString(const CyberTypes::HighPerformanceCounterInfo& input) {
    std::wostringstream os;
    os << "HPC: " << input.counter.QuadPart << " / " << input.frequency.QuadPart;
    return os.str();
}

// Convert CyberTypes::CoreInfo to CyberTypes::CyString
CyberTypes::CyString to_CyString(const CyberTypes::CoreInfo& input) {
    std::wostringstream os;
    os << "Core: " << input.logicalProcessorId << " - " << "Tick: " << input.processorTick;
    return os.str();
}

// Convert CyberTypes::RTC to CyberTypes::CyString
CyberTypes::CyString to_CyString(const CyberTypes::RTC& input) {
    std::wostringstream os;
    os << "RTC: " << input.timestamp;
    return os.str();
}

// Convert CyberTypes::SystemInfo to CyberTypes::CyString
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

// Convert CyberTypes::CT_NGX_Version_t to CyberTypes::CyString
CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Version_t& input) {
    std::wostringstream os;
    os << (DWORD)input;
    return os.str();
}

// Convert CyberTypes::CT_NGX_ProjectIdDescription_t to CyberTypes::CyString
CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_ProjectIdDescription_t& input) {
    std::wostringstream os;
    os << "Project ID: " << input.ProjectId << L", ";
    os << "Engine Type: " << input.EngineType << L", ";
    os << "Engine Version: " << input.EngineVersion;
    return os.str();
}

// Convert CyberTypes::CT_NGX_Application_Identifier_Type_t to CyberTypes::CyString
CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Application_Identifier_Type_t& input) {
    std::wostringstream os;
    os << L"NVSDK_NGX_Application_Identifier_Type: ";
    switch (input) {
    case NVSDK_NGX_Application_Identifier_Type_Application_Id:
        os << L"Application_Id";
        break;
    case NVSDK_NGX_Application_Identifier_Type_Project_Id:
        os << L"Project_Id";
        break;
    }
    return os.str();
}

// Helper function to convert NVSDK_NGX_Application_Identifier to CyString
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

CyberTypes::CyString to_CyString(const CyberTypes::CT_NGX_Result_t& result) {
    return CyberTypes::CyString(std::to_wstring(result));
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Result_t& result) {
    os << to_CyString(result);
    return os;
}

CyberTypes::CyString_view to_CyString(const CyberTypes::CT_NGX_Buffer_Format_t& bufferFormat) {
    switch (bufferFormat) {
        CyberEnumSwitchHelper(NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_Unknown);
        CyberEnumSwitchHelper(NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_RGB8UI);
        CyberEnumSwitchHelper(NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_RGB16F);
        CyberEnumSwitchHelper(NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_RGB32F);
        CyberEnumSwitchHelper(NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_RGBA8UI);
        CyberEnumSwitchHelper(NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_RGBA16F);
        CyberEnumSwitchHelper(NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_RGBA32F);
    default:
        return L"CI_Unknown";
    }
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_Buffer_Format_t& bufferFormat) {
    os << to_CyString(bufferFormat);
    return os;
}

CyberTypes::CyString_view to_CyString(const CyberTypes::CT_NGX_ToneMapperType_t& toneMapperType) {
    switch (toneMapperType) {
        CyberEnumSwitchHelper(NVSDK_NGX_TONEMAPPER_, NVSDK_NGX_TONEMAPPER_STRING);
        CyberEnumSwitchHelper(NVSDK_NGX_TONEMAPPER_, NVSDK_NGX_TONEMAPPER_REINHARD);
        CyberEnumSwitchHelper(NVSDK_NGX_TONEMAPPER_, NVSDK_NGX_TONEMAPPER_ONEOVERLUMA);
        CyberEnumSwitchHelper(NVSDK_NGX_TONEMAPPER_, NVSDK_NGX_TONEMAPPER_ACES);
        CyberEnumSwitchHelper(NVSDK_NGX_TONEMAPPER_, NVSDK_NGX_TONEMAPPERTYPE_NUM);
    default: 
        return L"CI_Unknown";
    }
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NGX_ToneMapperType_t& toneMapperType) {
    os << to_CyString(toneMapperType);
    return os;
}

CyberTypes::CyString_view to_CyString(const CyberTypes::CT_NGX_GBufferType_t& gBufferType) {
    switch (gBufferType) {
    CyberEnumSwitchHelper(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_ALBEDO);
    CyberEnumSwitchHelper(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_ROUGHNESS);
    CyberEnumSwitchHelper(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_METALLIC);
    CyberEnumSwitchHelper(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_SPECULAR);
    CyberEnumSwitchHelper(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_NORMALS);
    CyberEnumSwitchHelper(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_SHADINGMODELID);
    CyberEnumSwitchHelper(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_MATERIALID);
    CyberEnumSwitchHelper(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_SPECULAR_ALBEDO);
    CyberEnumSwitchHelper(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_INDIRECT_ALBEDO);
    CyberEnumSwitchHelper(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_SPECULAR_MVEC);
    CyberEnumSwitchHelper(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_DISOCCL_MASK);
    CyberEnumSwitchHelper(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_EMISSIVE);
    CyberEnumSwitchHelper(NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFERTYPE_NUM);
    default:
        return L"CI_Unknown";
    }
}

std::wostream& operator<<(std::wostream& os, const NVSDK_NGX_GBufferType& gBufferType) {
    os << to_CyString(gBufferType);
    return os;
}