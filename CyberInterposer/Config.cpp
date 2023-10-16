#include "pch.h"
#include "Config.h"

Config InterposerConfig = Config();

using AVT = Configurationator::AcceptedValueTypes;

Config::Config() {
    configData[L"DLSSBackEnd"][L"DLL"] = ini_value(L"CyberFSR.dll", AVT::String, {}, {});

    // QualityOverrides
    configData[L"QualityOverrides"].Comments = {
        L"",
        L"Default values:",
        L"Ultra Quality         : 1.3",
        L"Quality               : 1.5",
        L"Balanced              : 1.7",
        L"Performance           : 2.0",
        L"Ultra Performance     : 3.0",
        L"",
    };
    configData[L"QualityOverrides"][L"RatioUltraQuality"] = ini_value(1.3f, AVT::Float, {}, {});
    configData[L"QualityOverrides"][L"RatioQuality"] = ini_value(1.5f, AVT::Float, {}, {});
    configData[L"QualityOverrides"][L"RatioBalanced"] = ini_value(1.7f, AVT::Float, {}, {});
    configData[L"QualityOverrides"][L"RatioPerformance"] = ini_value(2.0f, AVT::Float, {}, {});
    configData[L"QualityOverrides"][L"RatioUltraPerformance"] = ini_value(3.0f, AVT::Float, {}, {});

    configData[L"QualityOverrides"][L"QualityRatioFixedResolutionOverrideEnabled"] = ini_value(false, AVT::Boolean, {}, { L"When Fixed Resolution is enabled any non-zero resolutions will be used in place of the ratio computed resolution" });
    configData[L"QualityOverrides"][L"QualityRatioFixedResolutionAxis"] = ini_value(L"height", AVT::String, {L"height", L"width"}, {});
    configData[L"QualityOverrides"][L"FixedResUltraQuality"] = ini_value(unsigned int(0), AVT::Unsigned_Integer, {}, {});
    configData[L"QualityOverrides"][L"FixedResQuality"] = ini_value(unsigned int(0), AVT::Unsigned_Integer, {}, {});
    configData[L"QualityOverrides"][L"FixedResBalanced"] = ini_value(unsigned int(0), AVT::Unsigned_Integer, {}, {});
    configData[L"QualityOverrides"][L"FixedResPerformance"] = ini_value(unsigned int(0), AVT::Unsigned_Integer, {}, {});
    configData[L"QualityOverrides"][L"FixedResUltraPerformance"] = ini_value(unsigned int(0), AVT::Unsigned_Integer, {}, {});

};