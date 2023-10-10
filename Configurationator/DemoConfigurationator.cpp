#include "pch.h"
#include "DemoConfigurationator.h"

using ACT = Configurationator::AcceptedValueTypes;

void DemoConfigurationator::loadDefaultValues() {
    // Depth
    configData["Depth"]["DepthInverted"] = ini_value(SpecialValue::Auto, ACT::Boolean, {}, { "true or false" });

    // Color
    configData["Color"]["AutoExposure"] = ini_value(SpecialValue::Auto, ACT::Boolean, {}, { "true or false" });
    configData["Color"]["HDR"] = ini_value(SpecialValue::Auto, ACT::Boolean, {}, { "true or false" });

    // MotionVectors
    configData["MotionVectors"]["JitterCancellation"] = ini_value(SpecialValue::Auto, ACT::Boolean, {}, { "true or false" });
    configData["MotionVectors"]["DisplayResolution"] = ini_value(SpecialValue::Auto, ACT::Boolean, {}, { "true or false" });

    // Sharpening
    configData["Sharpening"]["EnableSharpening"] = ini_value(SpecialValue::Auto, ACT::Boolean, {}, { "true or false" });
    configData["Sharpening"]["Sharpness"] = ini_value(SpecialValue::Auto, ACT::Float, {}, { "number between 0 and 1.0" });
    configData["Sharpening"]["SharpnessRange"] = ini_value(SpecialValue::Auto, ACT::String, { "normal", "extended" }, {});

    // UpscaleRatio
    configData["UpscaleRatio"]["UpscaleRatioOverrideEnabled"] = ini_value(SpecialValue::Auto, ACT::Boolean, {}, { "set this to true to enable the internal resolution override" });
    configData["UpscaleRatio"]["UpscaleRatioOverrideValue"] = ini_value(SpecialValue::Auto, ACT::Float, {}, {
        "set the forced upscale ratio value",
        "resolution values are calculated in this way:",
        "OutHeight = Height / ratio;",
        "OutWidth = Width / ratio;",
        "example ratios: Quality preset = 1.5; Ultra performance preset = 3.0"
        });

    // QualityOverrides
    configData["QualityOverrides"]["QualityRatioOverrideEnabled"] = ini_value(SpecialValue::Auto, ACT::Boolean, {}, { "set this to true to enable custom quality mode overrides" });
    configData["QualityOverrides"]["QualityRatioUltraQuality"] = ini_value(SpecialValue::Auto, ACT::Float, {}, { "Default values:", "Ultra Quality: 1.3" });
    configData["QualityOverrides"]["QualityRatioQuality"] = ini_value(SpecialValue::Auto, ACT::Float, {}, { "Default values:", "Quality: 1.5" });
    configData["QualityOverrides"]["QualityRatioBalanced"] = ini_value(SpecialValue::Auto, ACT::Float, {}, { "Default values:", "Balanced: 1.7" });
    configData["QualityOverrides"]["QualityRatioPerformance"] = ini_value(SpecialValue::Auto, ACT::Float, {}, { "Default values:", "Performance: 2.0" });
    configData["QualityOverrides"]["QualityRatioUltraPerformance"] = ini_value(SpecialValue::Auto, ACT::Float, {}, { "Default values:", "Ultra Performance: 3.0" });

    // View
    configData["View"]["Method"] = ini_value(SpecialValue::Auto, ACT::String, { "config", "cyberpunk2077", "rdr2", "dl2" }, { "config, cyberpunk2077 or rdr2 or dl2" });
    configData["View"]["VerticalFOV"] = ini_value(SpecialValue::Auto, ACT::Float, {}, { "number for the vertical field of view value", "use a convertor if you only know the horizontal field of view" });
    configData["View"]["NearPlane"] = ini_value(SpecialValue::Auto, ACT::Float, {}, { "number that is at least 0" });
    configData["View"]["FarPlane"] = ini_value(SpecialValue::Auto, ACT::Float, {}, { "number that is higher than the NearPlane value" });
    configData["View"]["InfiniteFarPlane"] = ini_value(SpecialValue::Auto, ACT::Boolean, {}, { "set this if the far clip plane is infinite" });

    // Hotfix
    configData["Hotfix"]["DisableReactiveMask"] = ini_value(false, ACT::Boolean, {}, { "true or false" });
};