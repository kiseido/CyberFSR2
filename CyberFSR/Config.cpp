#include "pch.h"
#include "Config.h"
#include "Util.h"

#include "pch.h"
#include "Config.h"

CFSRConfig InterposerConfig = CFSRConfig();

using AVT = Configurationator::AcceptedValueTypes;

CFSRConfig::CFSRConfig() {
	// Depth
	configData[L"Depth"][L"DepthInverted"] = ini_value(SpecialValue::Auto, AVT::Boolean, {}, { L"true or false" });

	// Color
	configData[L"Color"][L"AutoExposure"] = ini_value(SpecialValue::Auto, AVT::Boolean, {}, { L"true or false" });
	configData[L"Color"][L"HDR"] = ini_value(SpecialValue::Auto, AVT::Boolean, {}, { L"true or false" });

	// MotionVectors
	configData[L"MotionVectors"][L"JitterCancellation"] = ini_value(SpecialValue::Auto, AVT::Boolean, {}, { L"true or false" });
	configData[L"MotionVectors"][L"DisplayResolution"] = ini_value(SpecialValue::Auto, AVT::Boolean, {}, { L"true or false" });

	// Sharpening
	configData[L"Sharpening"][L"EnableSharpening"] = ini_value(SpecialValue::Auto, AVT::Boolean, {}, { L"true or false" });
	configData[L"Sharpening"][L"Sharpness"] = ini_value(SpecialValue::Auto, AVT::Float, {}, { L"number between 0 and 1.0" });
	configData[L"Sharpening"][L"SharpnessRange"] = ini_value(SpecialValue::Auto, AVT::String, { L"normal", L"extended" }, {});

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
	configData[L"QualityOverrides"][L"QualityRatioFixedResolutionAxis"] = ini_value(L"height", AVT::String, { L"height", L"width" }, {});
	configData[L"QualityOverrides"][L"FixedResUltraQuality"] = ini_value(unsigned int(0), AVT::Unsigned_Integer, {}, {});
	configData[L"QualityOverrides"][L"FixedResQuality"] = ini_value(unsigned int(0), AVT::Unsigned_Integer, {}, {});
	configData[L"QualityOverrides"][L"FixedResBalanced"] = ini_value(unsigned int(0), AVT::Unsigned_Integer, {}, {});
	configData[L"QualityOverrides"][L"FixedResPerformance"] = ini_value(unsigned int(0), AVT::Unsigned_Integer, {}, {});
	configData[L"QualityOverrides"][L"FixedResUltraPerformance"] = ini_value(unsigned int(0), AVT::Unsigned_Integer, {}, {});

	// View
	configData[L"View"][L"Method"] = ini_value(L"auto", AVT::String, { L"auto", L"config", L"cyberpunk2077", L"rdr2", L"dl2" }, { L"config, cyberpunk2077 or rdr2 or dl2" });
	configData[L"View"][L"VerticalFOV"] = ini_value(SpecialValue::Auto, AVTUtils::pack(AVT::SpecialValue, AVT::Float), {}, { L"number for the vertical field of view value", L"use a convertor if you only know the horizontal field of view" });
	configData[L"View"][L"NearPlane"] = ini_value(SpecialValue::Auto, AVTUtils::pack(AVT::SpecialValue, AVT::Float), {}, { L"number that is at least 0" });
	configData[L"View"][L"FarPlane"] = ini_value(SpecialValue::Auto, AVTUtils::pack(AVT::SpecialValue, AVT::Float), {}, { L"number that is higher than the NearPlane value" });
	configData[L"View"][L"InfiniteFarPlane"] = ini_value(SpecialValue::Auto, AVTUtils::pack(AVT::SpecialValue, AVT::Float), {}, { L"set this if the far clip plane is infinite" });

	// Hotfix
	configData[L"Hotfix"][L"DisableReactiveMask"] = ini_value(false, AVTUtils::pack(AVT::SpecialValue, AVT::Boolean), {}, { L"true or false" });
};

Config::Config(std::wstring fileName)
{
	absoluteFileName = Util::DllPath().parent_path() / fileName;

	Reload();
}

void Config::Reload()
{
	if (ini.LoadFile(absoluteFileName.c_str()) == SI_OK)
	{
		// Depth
		DepthInverted = readBool("Depth", "DepthInverted");

		// Color
		AutoExposure = readBool("Color", "AutoExposure");
		HDR = readBool("Color", "HDR");

		// MotionVectors
		JitterCancellation = readBool("MotionVectors", "JitterCancellation");
		DisplayResolution = readBool("MotionVectors", "DisplayResolution");

		// Sharpening
		EnableSharpening = readBool("Sharpening", "EnableSharpening");
		Sharpness = readFloat("Sharpening", "Sharpness");
		SharpnessRange = readSharpnessRange("Sharpening", "SharpnessRange");

		//Upscale Ratio Override
		UpscaleRatioOverrideEnabled = readBool("UpscaleRatio", "UpscaleRatioOverrideEnabled");
		UpscaleRatioOverrideValue = readFloat("UpscaleRatio", "UpscaleRatioOverrideValue");

		// Quality Overrides
		QualityRatioOverrideEnabled = readBool("QualityOverrides", "QualityRatioOverrideEnabled");
		if (QualityRatioOverrideEnabled) {
			QualityRatio_UltraQuality = readFloat("QualityOverrides", "QualityRatioUltraQuality");
			QualityRatio_Quality = readFloat("QualityOverrides", "QualityRatioQuality");
			QualityRatio_Balanced = readFloat("QualityOverrides", "QualityRatioBalanced");
			QualityRatio_Performance = readFloat("QualityOverrides", "QualityRatioPerformance");
			QualityRatio_UltraPerformance = readFloat("QualityOverrides", "QualityRatioUltraPerformance");
		}


		// View
		Method = readViewMethod("View", "Method");
		VerticalFOV = readFloat("View", "VerticalFOV");
		NearPlane = readFloat("View", "NearPlane");
		FarPlane = readFloat("View", "FarPlane");
		InfiniteFarPlane = readBool("View", "InfiniteFarPlane");

		DisableReactiveMask = readBool("Hotfix", "DisableReactiveMask");
	}

	auto exeName = Util::ExePath().filename();

	if (exeName == L"Cyberpunk2077.exe")
	{
		Method = Method.value_or(ViewMethod::Cyberpunk2077);
	}
	else if (exeName == L"DyingLightGame_x64_rwdi.exe")
	{
		Method = Method.value_or(ViewMethod::DL2);
	}
	else if (exeName == L"RDR2.exe")
	{
		Method = Method.value_or(ViewMethod::RDR2);
	}
}

std::optional<std::string> Config::readString(std::string section, std::string key, bool lowercase)
{
	std::string chars = ini.GetValue(section.c_str(), key.c_str(), "auto");

	std::string lower = chars;
	std::transform(
		lower.begin(), lower.end(),
		lower.begin(),
		[](unsigned char c)
		{
			return std::tolower(c);
		}
	);

	if (lower == "auto")
	{
		return std::nullopt;
	}
	return lowercase ? lower : chars;
}

std::optional<float> Config::readFloat(std::string section, std::string key)
{
	auto chars = readString(section, key);
	try
	{
		return std::stof(chars.chars());
	}
	catch (const std::bad_optional_access&) // missing or auto value
	{
		return std::nullopt;
	}
	catch (const std::invalid_argument&) // invalid float string for std::stof
	{
		return std::nullopt;
	}
	catch (const std::out_of_range&) // out of range for 32 bit float
	{
		return std::nullopt;
	}
}

std::optional<bool> Config::readBool(std::string section, std::string key)
{
	auto chars = readString(section, key, true);
	if (chars == "true")
	{
		return true;
	}
	else if (chars == "false")
	{
		return false;
	}

	return std::nullopt;
}

std::optional<SharpnessRangeModifier> Config::readSharpnessRange(std::string section, std::string key)
{
	auto chars = readString(section, key, true);
	if (chars == "normal")
	{
		return SharpnessRangeModifier::Normal;
	}
	else if (chars == "extended")
	{
		return SharpnessRangeModifier::Extended;
	}

	return std::nullopt;
}

std::optional<ViewMethod> Config::readViewMethod(std::string section, std::string key)
{
	auto chars = readString(section, key, true);
	if (chars == "config")
	{
		return ViewMethod::Config;
	}
	else if (chars == "cyberpunk2077")
	{
		return ViewMethod::Cyberpunk2077;
	}
	else if (chars == "rdr2")
	{
		return ViewMethod::RDR2;
	}
	else if (chars == "dl2")
	{
		return ViewMethod::DL2;
	}

	return std::nullopt;
}
