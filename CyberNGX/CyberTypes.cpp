#include "pch.h"

#include "CyberTypes.h"

#include "CyberMacro.h"

namespace CyberTypes {

    DLSS_Feature_Flags_Wrapper& DLSS_Feature_Flags_Wrapper::operator=(const NVSDK_NGX_DLSS_Feature_Flags& other) {
        this->inner = other;
        return *this;
    }

    DLSS_Feature_Flags_Wrapper::operator NVSDK_NGX_DLSS_Feature_Flags() const {
        return this->inner;
    }

    bool DLSS_Feature_Flags_Wrapper::IsHDR() {
        return (inner & NVSDK_NGX_DLSS_Feature_Flags_IsHDR) != 0;
    }

    bool DLSS_Feature_Flags_Wrapper::IsMVLowRes() {
        return (inner & NVSDK_NGX_DLSS_Feature_Flags_MVLowRes) != 0;
    }

    bool DLSS_Feature_Flags_Wrapper::IsMVJittered() {
        return (inner & NVSDK_NGX_DLSS_Feature_Flags_MVJittered) != 0;
    }

    bool DLSS_Feature_Flags_Wrapper::IsDepthInverted() {
        return (inner & NVSDK_NGX_DLSS_Feature_Flags_DepthInverted) != 0;
    }

    bool DLSS_Feature_Flags_Wrapper::IsReserved0() {
        return (inner & NVSDK_NGX_DLSS_Feature_Flags_Reserved_0) != 0;
    }

    bool DLSS_Feature_Flags_Wrapper::IsDoSharpening() {
        return (inner & NVSDK_NGX_DLSS_Feature_Flags_DoSharpening) != 0;
    }

    bool DLSS_Feature_Flags_Wrapper::IsAutoExposure() {
        return (inner & NVSDK_NGX_DLSS_Feature_Flags_AutoExposure) != 0;
    }
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
        LARGE_INTEGER freq;
        LARGE_INTEGER count;

        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&count);

        frequency = freq.QuadPart;
        counter = count.QuadPart;
    }
    else {
        frequency = 0;
        counter = 0;
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

CyberTypes::CyString to_CyString(const char str[])
{
    return CyberTypes::CyString(std::string_view(str));
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

CyberTypes::CyString::CyString(const std::wstring_view& wview) : std::wstring(wview){}

CyberTypes::CyString::CyString(const std::string& str) : CyString(stringToWstring(str)){}

CyberTypes::CyString::CyString(const std::string_view& view) : CyString(stringToWstring(std::string(view))){}

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

//

std::wostream& operator<<(std::wostream& os, const CyberTypes::HighPerformanceCounterInfo& counterInfo) {
    os << "HPC: " << counterInfo.counter << " / " << counterInfo.frequency;
    return os;
}

//

std::wostream& operator<<(std::wostream& os, const CyberTypes::CoreInfo& coreInfo) {
    os << "Core: " << coreInfo.logicalProcessorId << " - " << "Tick: " << coreInfo.processorTick;
    return os;
}

//

std::wostream& operator<<(std::wostream& os, const CyberTypes::RTC& rtc) {
    os << "RTC: " << rtc.timestamp;
    return os;
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

//

std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_Version_u& version) {
    os << (DWORD)version.inner;
    return os;
}

//


std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_Application_Identifier_Type_u& identifierType) {
    os << "NVSDK_NGX_Application_Identifier_Type: ";
    switch (identifierType.inner) {
        os << "NVSDK_NGX_Application_Identifier_Type: ";
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Application_Identifier_Type_, NVSDK_NGX_Application_Identifier_Type_Application_Id);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Application_Identifier_Type_, NVSDK_NGX_Application_Identifier_Type_Project_Id);
    default:
        os << L"CI_Unknown";
    }
    return os;
}

//

std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_ProjectIdDescription_u& obj) {
    const NVSDK_NGX_ProjectIdDescription& inner = obj.inner;
    os << "Project ID: " << inner.ProjectId << ", ";
    os << "Engine Type: " << inner.EngineType << ", ";
    os << "Engine Version: " << inner.EngineVersion;
    return os;
}

//

std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_Application_Identifier_u& identifier) {

    switch (identifier.inner.IdentifierType) {
    case NVSDK_NGX_Application_Identifier_Type_Application_Id: {
        const CyberTypes::CT_NVSDK_NGX_Application_Identifier_Type_u& appid = (CyberTypes::CT_NVSDK_NGX_Application_Identifier_Type_u&) (identifier.inner.IdentifierType);
        os << appid;
        break;
    }
    case NVSDK_NGX_Application_Identifier_Type_Project_Id:
    {
        const CyberTypes::CT_NVSDK_NGX_ProjectIdDescription_u& pidDesc = (CyberTypes::CT_NVSDK_NGX_ProjectIdDescription_u&)(identifier.inner.v.ProjectDesc);
        os << pidDesc;
        break;
    }
    default:
        os << L"CI_Unknown";
    }

    return os;
}


std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_Result_u& result) {
    os << std::to_wstring(result.inner);
    return os;
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_Buffer_Format_u& bufferFormat) {
    switch (bufferFormat.inner) {
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_Unknown);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_RGB8UI);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_RGB16F);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_RGB32F);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_RGBA8UI);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_RGBA16F);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Buffer_Format_, NVSDK_NGX_Buffer_Format_RGBA32F);
    default:
        os << L"CI_Unknown";
    }
    return os;
}


std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_ToneMapperType_u& toneMapperType) {
    switch (toneMapperType.inner) {
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_TONEMAPPER_, NVSDK_NGX_TONEMAPPER_STRING);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_TONEMAPPER_, NVSDK_NGX_TONEMAPPER_REINHARD);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_TONEMAPPER_, NVSDK_NGX_TONEMAPPER_ONEOVERLUMA);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_TONEMAPPER_, NVSDK_NGX_TONEMAPPER_ACES);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_TONEMAPPER_, NVSDK_NGX_TONEMAPPERTYPE_NUM);
    default:
        os <<  L"CI_Unknown";
    }
    return os;
}


std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_GBufferType_u& gBufferType) {
    switch (gBufferType.inner) {
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_ALBEDO);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_ROUGHNESS);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_METALLIC);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_SPECULAR);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_NORMALS);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_SHADINGMODELID);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_MATERIALID);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_SPECULAR_ALBEDO);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_INDIRECT_ALBEDO);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_SPECULAR_MVEC);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_DISOCCL_MASK);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFER_EMISSIVE);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_GBUFFER_, NVSDK_NGX_GBUFFERTYPE_NUM);
    default:
        os << L"CI_Unknown";
    }
    return os;
}

std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_Feature_u& input) {
    switch (input.inner) {
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Feature_, NVSDK_NGX_Feature_Reserved0);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Feature_, NVSDK_NGX_Feature_SuperSampling);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Feature_, NVSDK_NGX_Feature_InPainting);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Feature_, NVSDK_NGX_Feature_ImageSuperResolution);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Feature_, NVSDK_NGX_Feature_SlowMotion);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Feature_, NVSDK_NGX_Feature_VideoSuperResolution);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Feature_, NVSDK_NGX_Feature_Reserved1);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Feature_, NVSDK_NGX_Feature_Reserved2);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Feature_, NVSDK_NGX_Feature_Reserved3);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Feature_, NVSDK_NGX_Feature_ImageSignalProcessing);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Feature_, NVSDK_NGX_Feature_DeepResolve);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Feature_, NVSDK_NGX_Feature_DeepDVC);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Feature_, NVSDK_NGX_Feature_Reserved13);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Feature_, NVSDK_NGX_Feature_Count);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Feature_, NVSDK_NGX_Feature_Reserved_SDK);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Feature_, NVSDK_NGX_Feature_Reserved_Core);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_Feature_, NVSDK_NGX_Feature_Reserved_Unknown);
    default:
        os << L"CI_Unknown";
    }
    return os;
}

// CT_NVSDK_NGX_Coordinates_u

std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_Coordinates_u& coordinates) {
    os << L"(" << std::to_wstring(coordinates.inner.X) << L", " << std::to_wstring(coordinates.inner.Y) << L")";
    return os;
}

// CT_NVSDK_NGX_Dimensions_u

std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_Dimensions_u& dimensions) {
    os << L"[" << std::to_wstring(dimensions.inner.Width) << L"x" << std::to_wstring(dimensions.inner.Height) << L"]";
    return os;
}

std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_PathListInfo_u& pathListInfo) {
    os << L"[";
    for (unsigned int i = 0; i < pathListInfo.inner.Length; ++i) {
        os << pathListInfo.inner.Path[i];
        if (i < pathListInfo.inner.Length - 1) {
            os << L", ";
        }
    }
    os << L"]";
    return os;
}


std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_Logging_Level_u& loggingLevel) {
    switch (loggingLevel.inner) {
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_LOGGING_LEVEL_, NVSDK_NGX_LOGGING_LEVEL_OFF);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_LOGGING_LEVEL_, NVSDK_NGX_LOGGING_LEVEL_ON);
        CyberEnumSwitchHelperOStream(os ,NVSDK_NGX_LOGGING_LEVEL_, NVSDK_NGX_LOGGING_LEVEL_VERBOSE);
    default:
        os << L"CI_Unknown";
    }
    return os;
}


std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_Resource_VK_Type_u& resourceVKType) {
    switch (resourceVKType.inner) {
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_RESOURCE_VK_TYPE_, NVSDK_NGX_RESOURCE_VK_TYPE_VK_IMAGEVIEW);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_RESOURCE_VK_TYPE_, NVSDK_NGX_RESOURCE_VK_TYPE_VK_BUFFER);
    default:
        os << L"CI_Unknown";
    }
    return os;
}

// CT_NVSDK_NGX_Opt_Level_u

std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_Opt_Level_u& optLevel) {
    switch (optLevel.inner) {
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_OPT_LEVEL_, NVSDK_NGX_OPT_LEVEL_UNDEFINED);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_OPT_LEVEL_, NVSDK_NGX_OPT_LEVEL_DEBUG);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_OPT_LEVEL_, NVSDK_NGX_OPT_LEVEL_DEVELOP);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_OPT_LEVEL_, NVSDK_NGX_OPT_LEVEL_RELEASE);
    default:
        os << L"CI_Unknown";
    };
    return os;
}


// CT_NVSDK_NGX_EngineType_u


std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_EngineType_u& engineType) {
    switch (engineType.inner) {
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_ENGINE_TYPE_, NVSDK_NGX_ENGINE_TYPE_CUSTOM);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_ENGINE_TYPE_, NVSDK_NGX_ENGINE_TYPE_UNREAL);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_ENGINE_TYPE_, NVSDK_NGX_ENGINE_TYPE_UNITY);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_ENGINE_TYPE_, NVSDK_NGX_ENGINE_TYPE_OMNIVERSE);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_ENGINE_TYPE_, NVSDK_NGX_ENGINE_COUNT);
    default:
        os << L"CI_Unknown";
    }
    return os;
}

std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_Feature_Support_Result_u& featureSupportResult) {
    switch (featureSupportResult.inner) {
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_FeatureSupportResult_, NVSDK_NGX_FeatureSupportResult_Supported);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_FeatureSupportResult_, NVSDK_NGX_FeatureSupportResult_CheckNotPresent);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_FeatureSupportResult_, NVSDK_NGX_FeatureSupportResult_DriverVersionUnsupported);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_FeatureSupportResult_, NVSDK_NGX_FeatureSupportResult_AdapterUnsupported);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_FeatureSupportResult_, NVSDK_NGX_FeatureSupportResult_OSVersionBelowMinimumSupported);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_FeatureSupportResult_, NVSDK_NGX_FeatureSupportResult_NotImplemented);
    default:
        os << L"CI_Unknown";
    }
    return os;
}

// CT_AppId_t

std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_AppId_u& appId) {
    os << (unsigned long long) appId.inner;
    return os;
}

std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_GPU_Arch_u& gpuArch) {
    switch (gpuArch.inner) {
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_GPU_Arch_, NVSDK_NGX_GPU_Arch_NotSupported);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_GPU_Arch_, NVSDK_NGX_GPU_Arch_Volta);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_GPU_Arch_, NVSDK_NGX_GPU_Arch_Turing);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_GPU_Arch_, NVSDK_NGX_GPU_Arch_Unknown);
    default:
        os << L"CI_Unknown";
    }
    return os;
}


std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_DLSS_Hint_Render_Preset_u& renderPreset) {
    switch (renderPreset.inner) {
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_DLSS_Hint_Render_Preset_, NVSDK_NGX_DLSS_Hint_Render_Preset_Default);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_DLSS_Hint_Render_Preset_, NVSDK_NGX_DLSS_Hint_Render_Preset_A);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_DLSS_Hint_Render_Preset_, NVSDK_NGX_DLSS_Hint_Render_Preset_B);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_DLSS_Hint_Render_Preset_, NVSDK_NGX_DLSS_Hint_Render_Preset_C);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_DLSS_Hint_Render_Preset_, NVSDK_NGX_DLSS_Hint_Render_Preset_D);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_DLSS_Hint_Render_Preset_, NVSDK_NGX_DLSS_Hint_Render_Preset_E);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_DLSS_Hint_Render_Preset_, NVSDK_NGX_DLSS_Hint_Render_Preset_F);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_DLSS_Hint_Render_Preset_, NVSDK_NGX_DLSS_Hint_Render_Preset_G);
    default:
        os << L"CI_Unknown";
    }
    return os;
}

std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_DLSS_Mode_u& dlssMode) {
    switch (dlssMode.inner) {
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_DLSS_Mode_, NVSDK_NGX_DLSS_Mode_Off);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_DLSS_Mode_, NVSDK_NGX_DLSS_Mode_DLSS_DLISP);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_DLSS_Mode_, NVSDK_NGX_DLSS_Mode_DLISP_Only);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_DLSS_Mode_, NVSDK_NGX_DLSS_Mode_DLSS);
    default:
        os << L"CI_Unknown";
    }
    return os;
}


std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_DeepDVC_Mode_u& deepDVCMode) {
    switch (deepDVCMode.inner) {
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_DLSS_DeepDVC_Mode_, NVSDK_NGX_DLSS_DeepDVC_Mode_Off);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_DLSS_DeepDVC_Mode_, NVSDK_NGX_DLSS_DeepDVC_Mode_On);
    default:
        os << L"CI_Unknown";
    }
    return os;
}

std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_FeatureCommonInfo_Internal_u& featureCommonInfo) {
    os << L"FeatureCommonInfo_Internal";
    return os;
}

std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_Handle_u& ngxHandle) {
    os << std::to_wstring(ngxHandle.inner.Id);
    return os;
}


std::wostream& CyberTypes::operator<<(std::wostream& os, const CyberTypes::CT_NVSDK_NGX_FeatureRequirement_u& featureRequirement) {

    os << L"Feature Supported: ";
    switch (featureRequirement.inner.FeatureSupported) {
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_FeatureSupportResult_, NVSDK_NGX_FeatureSupportResult_Supported);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_FeatureSupportResult_, NVSDK_NGX_FeatureSupportResult_CheckNotPresent);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_FeatureSupportResult_, NVSDK_NGX_FeatureSupportResult_DriverVersionUnsupported);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_FeatureSupportResult_, NVSDK_NGX_FeatureSupportResult_AdapterUnsupported);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_FeatureSupportResult_, NVSDK_NGX_FeatureSupportResult_OSVersionBelowMinimumSupported);
        CyberEnumSwitchHelperOStream(os, NVSDK_NGX_FeatureSupportResult_, NVSDK_NGX_FeatureSupportResult_NotImplemented);
    default:
        os << L"Unknown";
        break;
    }

    // Add a separator (e.g., a comma) between members or use any other appropriate format.
    os << L", ";

    // Convert the MinHWArchitecture to a string.
    os << L"Minimum HW Architecture: " << std::to_wstring(featureRequirement.inner.MinHWArchitecture);

    // Add another separator.
    os << L", ";

    // Convert the MinOSVersion to a string.
    os << L"Minimum OS Version: " << to_CyString(std::string_view(featureRequirement.inner.MinOSVersion));

    return os;
}
