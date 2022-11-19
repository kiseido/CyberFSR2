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
			UpscalerProfile = readUpscalingProfile("Upscaling", "UpscalerProfile").value_or(UpscalingProfile::DLSS2);

			// Quality Overrides
			Divisor_Auto = readFloat("QualityOverrides", "Auto").value_or(0);
			Divisor_UltraQuality = readFloat("QualityOverrides", "UltraQuality").value_or(0);
			Divisor_Quality = readFloat("QualityOverrides", "Quality").value_or(0);
			Divisor_Balanced = readFloat("QualityOverrides", "Balanced").value_or(0);
			Divisor_Performance = readFloat("QualityOverrides", "Performance").value_or(0);
			Divisor_UltraPerformance = readFloat("QualityOverrides", "UltraPerformance").value_or(0);

			// Quality Overrides
			Resolution_Auto = readScreenDimensions("StaticResolution", "Auto").value_or(std::pair{ 0,0 });
			Resolution_UltraQuality = readScreenDimensions("StaticResolution", "UltraQuality").value_or(std::pair{ 1600,900 });
			Resolution_Quality = readScreenDimensions("StaticResolution", "Quality").value_or(std::pair{ 1312,738 });
			Resolution_Balanced = readScreenDimensions("StaticResolution", "Balanced").value_or(std::pair{ 1024,576 });
			Resolution_Performance = readScreenDimensions("StaticResolution", "Performance").value_or(std::pair{ 736,495 });
			Resolution_UltraPerformance = readScreenDimensions("StaticResolution", "UltraPerformance").value_or(std::pair{ 448,252 });

			// Quality Overrides
			FPSTarget_Auto = readScreenDimensions("FPSTarget", "UltraQuality").value_or(std::pair{ 0,0 });
			FPSTarget_UltraQuality = readScreenDimensions("FPSTarget", "UltraQuality").value_or(std::pair{ 0,0 });
			FPSTarget_Quality = readScreenDimensions("FPSTarget", "Quality").value_or(std::pair{ 0,0 });
			FPSTarget_Balanced = readScreenDimensions("FPSTarget", "Balanced").value_or(std::pair{ 0,0 });
			FPSTarget_Performance = readScreenDimensions("FPSTarget", "Performance").value_or(std::pair{ 0,0 });
			FPSTarget_UltraPerformance = readScreenDimensions("FPSTarget", "UltraPerformance").value_or(std::pair{ 0,0 });

			UE_DepthInverted = readBool("EngineUnreal", "DepthInverted").value_or(false) ? Trinary::ON : Trinary::OFF;
			UE_JitterCancellation = readBool("EngineUnreal", "JitterCancellation").value_or(false) ? Trinary::ON : Trinary::OFF;
			UE_DisplayResolution = readBool("EngineUnreal", "DisplayResolution").value_or(false) ? Trinary::ON : Trinary::OFF;
			UE_NearPlane = readFloat("EngineUnreal", "NearPlane").value_or(false) ? Trinary::ON : Trinary::OFF;
			UE_FarPlane = readFloat("EngineUnreal", "FarPlane").value_or(false) ? Trinary::ON : Trinary::OFF;
			UE_InfiniteFarPlane = readBool("EngineUnreal", "InfiniteFarPlane").value_or(false) ? Trinary::ON : Trinary::OFF;

			Unity_DepthInverted = readBool("EngineUnreal", "DepthInverted").value_or(false) ? Trinary::ON : Trinary::OFF;
			Unity_JitterCancellation = readBool("EngineUnreal", "JitterCancellation").value_or(false) ? Trinary::ON : Trinary::OFF;
			Unity_DisplayResolution = readBool("EngineUnreal", "DisplayResolution").value_or(false) ? Trinary::ON : Trinary::OFF;
			Unity_NearPlane = readFloat("EngineUnreal", "NearPlane").value_or(false) ? Trinary::ON : Trinary::OFF;
			Unity_FarPlane = readFloat("EngineUnreal", "FarPlane").value_or(false) ? Trinary::ON : Trinary::OFF;
			Unity_InfiniteFarPlane = readBool("EngineUnreal", "InfiniteFarPlane").value_or(false) ? Trinary::ON : Trinary::OFF;

			Omniverse_DepthInverted = readBool("EngineUnreal", "DepthInverted").value_or(false) ? Trinary::ON : Trinary::OFF;
			Omniverse_JitterCancellation = readBool("EngineUnreal", "JitterCancellation").value_or(false) ? Trinary::ON : Trinary::OFF;
			Omniverse_DisplayResolution = readBool("EngineUnreal", "DisplayResolution").value_or(false) ? Trinary::ON : Trinary::OFF;
			Omniverse_NearPlane = readFloat("EngineUnreal", "NearPlane").value_or(false) ? Trinary::ON : Trinary::OFF;
			Omniverse_FarPlane = readFloat("EngineUnreal", "FarPlane").value_or(false) ? Trinary::ON : Trinary::OFF;
			Omniverse_InfiniteFarPlane = readBool("EngineUnreal", "InfiniteFarPlane").value_or(false) ? Trinary::ON : Trinary::OFF;
		}
		else
		{

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
		auto value = ini.GetValue(section.c_str(), key.c_str(), "auto");

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

	std::optional<UpscalingProfile> Config::readUpscalingProfile(std::string section, std::string key)
	{
		std::optional<UpscalingProfile> output = std::nullopt;
		std::optional<std::string> valueOpt = readString(section, key);
		if (valueOpt.has_value())
		{
			output = Util::UpscalingProfileMap(valueOpt.value().c_str());
		}
		return output;
		//return std::nullopt;
	}

	std::optional<ScreenDimensions> Config::readScreenDimensions(std::string section, std::string key)
	{
		std::optional<ScreenDimensions> output = std::nullopt;
		std::optional<std::string> valueOpt = readString(section, key);
		if (valueOpt.has_value())
		{
			try
			{
				constexpr auto delimiter = "x";
				const auto& values = valueOpt.value();
				const size_t delimiterLocation = values.find(delimiter);
				auto width = values.substr(0, delimiterLocation);
				auto height = values.substr(1, delimiterLocation);
				ScreenDimensions out;
				out.second = std::stoi(height);
				out.first = std::stoi(width);
				output = out;
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
		}

		return output;
	}

	std::optional<float> Config::readFloat(std::string section, std::string key)
	{
		std::optional<float> output = std::nullopt;
		std::optional<std::string> valueOpt = readString(section, key);
		if (valueOpt.has_value())
		{
			try
			{
				output = std::stof(valueOpt.value());
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
			else {
				//?!?
			}
		}

		return output;
	}

	std::optional<SharpnessRangeModifier> Config::readSharpnessRange(std::string section, std::string key)
	{
		std::optional<SharpnessRangeModifier> output = std::nullopt;
		auto valueOpt = readString(section, key, true);

		if (valueOpt.has_value())
			output = Util::SharpnessRangeModifierMap(valueOpt.value().c_str());

		return output;
	}

	std::optional<ViewMethod> Config::readViewMethod(std::string section, std::string key)
	{
		std::optional<ViewMethod> output = std::nullopt;
		auto valueOpt = readString(section, key, true);

		if (valueOpt.has_value())
			output = Util::ViewMethodMap(valueOpt.value().c_str());

		return output;
	}
}