#include "pch.h"
#include "Config.h"
#include "Util.h"

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
