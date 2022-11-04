#include "pch.h"
#include "Config.h"
#include "Util.h"

namespace CyberFSR
{
	Config::Config(std::string fileName)
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

		// Dynamic Scaler
		DynamicScalerEnabled = readBool("DynamicResolution", "DynamicScalerEnabled");
		FPSTarget = readFloat("DynamicResolution", "FPSTarget");
		FPSTargetMin = readFloat("DynamicResolution", "FPSTargetMin");
		FPSTargetMax = readFloat("DynamicResolution", "FPSTargetMax");
		FPSTargetResolutionMin = readFloat("DynamicResolution", "FPSTargetResolutionMin");
		FPSTargetResolutionMax = readFloat("DynamicResolution", "FPSTargetResolutionMax");
		
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
		ViewHookMethod = readViewMethod("View", "Method");
		VerticalFOV = readFloat("View", "VerticalFOV");
		NearPlane = readFloat("View", "NearPlane");
		FarPlane = readFloat("View", "FarPlane");
		InfiniteFarPlane = readBool("View", "InfiniteFarPlane");

			DisableReactiveMask = readBool("Hotfix", "DisableReactiveMask");

			// Upscale type
			UpscalerProfile = UpscalingProfile::DLSS2;//readUpscalingProfile("Upscaling", "UpscalerProfile").value_or(UpscalingProfile::DLSS2);

			StaticRatioOverride = readFloat("Upscaling", "Static_Ratio");

			// Quality Overrides
			QualityRatio_UltraQuality = readFloat("Upscaling", "Divisor_UltraQuality");
			QualityRatio_Quality = readFloat("Upscaling", "Divisor_Quality");
			QualityRatio_Balanced = readFloat("Upscaling", "Divisor_Balanced");
			QualityRatio_Performance = readFloat("Upscaling", "Divisor_Performance");
			QualityRatio_UltraPerformance = readFloat("Upscaling", "Divisor_UltraPerformance");

			// Quality Overrides
			QualityRatio_UltraQuality = readFloat("Upscaling", "Resolution_UltraQuality");
			QualityRatio_Quality = readFloat("Upscaling", "Resolution_Quality");
			QualityRatio_Balanced = readFloat("Upscaling", "Resolution_Balanced");
			QualityRatio_Performance = readFloat("Upscaling", "Resolution_Performance");
			QualityRatio_UltraPerformance = readFloat("Upscaling", "Resolution_UltraPerformance");
		}

		auto exeName = Util::ExePath().filename();

		if (exeName == "Cyberpunk2077.exe")
		{
			ViewHookMethod = ViewHookMethod.value_or(ViewMethod::Cyberpunk2077);
		}
		else if (exeName == "DyingLightGame_x64_rwdi.exe")
		{
			SharpnessRange = SharpnessRange.value_or(SharpnessRangeModifier::Extended);
		}
		else if (exeName == "RDR2.exe")
		{
			ViewHookMethod = ViewHookMethod.value_or(ViewMethod::RDR2);
		}
	}

	std::optional<std::string> Config::readString(std::string section, std::string key, bool lowercase)
	{
		std::optional<std::string> output = std::nullopt;
		std::string value = ini.GetValue(section.c_str(), key.c_str(), "auto");

		std::string lower = value;
		std::transform(
			lower.begin(), lower.end(),
			lower.begin(),
			[](unsigned char c)
			{
				return std::tolower(c);
			}
		);

		if (lower != "auto")
			output = lowercase ? lower : value;

		return output;
	}

	std::optional<float> Config::readFloat(std::string section, std::string key)
	{
		std::optional<float> output = std::nullopt;
		auto value = readString(section, key);
		try
		{
			output = std::stof(value.value());
		}
		catch (const std::bad_optional_access&) // missing or auto value
		{
			output = std::nullopt;
		}
		catch (const std::invalid_argument&) // invalid float string for std::stof
		{
			output = std::nullopt;
		}
		catch (const std::out_of_range&) // out of range for 32 bit float
		{
			output = std::nullopt;
		}

		return output;
	}

	std::optional<bool> Config::readBool(std::string section, std::string key)
	{
		std::optional<bool> output = std::nullopt;
		auto valueOpt = readString(section, key, true);

		if (valueOpt.has_value()) {
			const std::string& value = valueOpt.value();

			if (value.compare("true") == 0)
			{
				output = true;
			}
			else if (value.compare("false") == 0)
			{
				output = false;
			}
		}

		return output;
	}

	std::optional<SharpnessRangeModifier> Config::readSharpnessRange(std::string section, std::string key)
	{
		std::optional<SharpnessRangeModifier> output = std::nullopt;
		auto value = readString(section, key, true);

		if (value)
			output = Util::SharpnessRangeModifierMap(value.value().c_str());

		return output;
	}

	std::optional<ViewMethod> Config::readViewMethod(std::string section, std::string key)
	{
		std::optional<ViewMethod> output = std::nullopt;
		auto value = readString(section, key, true);

		if (value)
			output = Util::ViewMethodMap(value.value().c_str());

		return output;
	}
}