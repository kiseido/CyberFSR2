#include "pch.h"
#include "DemoConfigurationator.h"

using AVT = Configurationator::AcceptedValueTypes;

DemoConfigurationator::DemoConfigurationator() {
    // Depth
    configData["Depth"]["DepthInverted"] = ini_value(SpecialValue::Auto, AVT::Boolean, {}, { "true or false" });

    // Color
    configData["Color"]["AutoExposure"] = ini_value(SpecialValue::Auto, AVT::Boolean, {}, { "true or false" });
    configData["Color"]["HDR"] = ini_value(SpecialValue::Auto, AVT::Boolean, {}, { "true or false" });

    // MotionVectors
    configData["MotionVectors"]["JitterCancellation"] = ini_value(SpecialValue::Auto, AVT::Boolean, {}, { "true or false" });
    configData["MotionVectors"]["DisplayResolution"] = ini_value(SpecialValue::Auto, AVT::Boolean, {}, { "true or false" });

    // Sharpening
    configData["Sharpening"]["EnableSharpening"] = ini_value(SpecialValue::Auto, AVT::Boolean, {}, { "true or false" });
    configData["Sharpening"]["Sharpness"] = ini_value(SpecialValue::Auto, AVT::Float, {}, { "number between 0 and 1.0" });
    configData["Sharpening"]["SharpnessRange"] = ini_value(SpecialValue::Auto, AVT::String, { "normal", "extended" }, {});

    // UpscaleRatio

    configData["UpscaleRatio"]["UpscaleRatioOverrideEnabled"] = ini_value(SpecialValue::Auto, AVT::Boolean, {}, { "set this to true to enable the internal resolution override" });
    configData["UpscaleRatio"]["UpscaleRatioOverrideValue"] = ini_value(SpecialValue::Auto, AVT::Float, {}, {
        "set the forced upscale ratio value",
        "resolution values are calculated in this way:",
        "OutHeight = Height / ratio;",
        "OutWidth = Width / ratio;",
        "example ratios: Quality preset = 1.5; Ultra performance preset = 3.0"
        });

    // QualityOverrides
    configData["QualityOverrides"].Comments = { 
        "",
        "Default values:",
        "Ultra Quality         : 1.3",
        "Quality               : 1.5",
        "Balanced              : 1.7",
        "Performance           : 2.0",
        "Ultra Performance     : 3.0",
        "",
    };
    configData["QualityOverrides"]["QualityRatioOverrideEnabled"] = ini_value(true, AVT::Boolean, {}, {"set this to true to enable custom quality mode overrides"});
    configData["QualityOverrides"]["QualityRatioUltraQuality"] = ini_value(1.3f, AVT::Float, {}, { "Default values:", "Ultra Quality: 1.3" });
    configData["QualityOverrides"]["QualityRatioQuality"] = ini_value(1.5f, AVT::Float, {}, { "Default values:", "Quality: 1.5" });
    configData["QualityOverrides"]["QualityRatioBalanced"] = ini_value(1.7f, AVT::Float, {}, { "Default values:", "Balanced: 1.7" });
    configData["QualityOverrides"]["QualityRatioPerformance"] = ini_value(2.0f, AVT::Float, {}, { "Default values:", "Performance: 2.0" });
    configData["QualityOverrides"]["QualityRatioUltraPerformance"] = ini_value(3.0f, AVT::Float, {}, { "Default values:", "Ultra Performance: 3.0" });

    // View
    configData["View"]["Method"] = ini_value("auto", AVT::String, {"auto", "config", "cyberpunk2077", "rdr2", "dl2"}, {"config, cyberpunk2077 or rdr2 or dl2"});
    configData["View"]["VerticalFOV"] = ini_value(SpecialValue::Auto, AVTUtils::pack(AVT::SpecialValue,AVT::Float), {}, {"number for the vertical field of view value", "use a convertor if you only know the horizontal field of view"});
    configData["View"]["NearPlane"] = ini_value(SpecialValue::Auto, AVTUtils::pack(AVT::SpecialValue, AVT::Float), {}, { "number that is at least 0" });
    configData["View"]["FarPlane"] = ini_value(SpecialValue::Auto, AVTUtils::pack(AVT::SpecialValue, AVT::Float), {}, { "number that is higher than the NearPlane value" });
    configData["View"]["InfiniteFarPlane"] = ini_value(SpecialValue::Auto, AVTUtils::pack(AVT::SpecialValue, AVT::Float), {}, { "set this if the far clip plane is infinite" });

    // Hotfix
    configData["Hotfix"]["DisableReactiveMask"] = ini_value(false, AVTUtils::pack(AVT::SpecialValue, AVT::Boolean), {}, { "true or false" });
};

int main() {
    DemoConfigurationator demoConfig;

    // Load configuration from the local demo.ini file
    demoConfig.loadFromFile("demo.ini");

    // Assuming some changes are made to the config (you can add this if necessary)

    // Save the updated configuration back to the same file
    demoConfig.saveToFile("demo.ini");

    return 0;
}