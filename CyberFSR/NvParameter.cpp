#include "pch.h"
#include "Config.h"
#include "Util.h"
#include "NvParameter.h"
#include "CyberFsr.h"

#include <numeric>
#include <algorithm>

#include <iostream>
#include <unordered_map>
#include <variant>
#include <cmath>
#include <vector>
#include <utility>

namespace Hyper_NGX {


	void HandlerDB_t::addHandlerLogic(NGX_Strings::MacroStrings_enum_t key, Handler_t logic) {
		handlers.emplace(key, logic);
	}

	Handler_t::HandlerStatus_t HandlerDB_t::Apply(ParameterDB_t& db, CallEvent_t& event) {
		auto range = handlers.equal_range(event.key);
		for (auto it = range.first; it != range.second; ++it) {
			Handler_t::HandlerStatus_t status = it->second.ApplyFunc(db, event);
			if (status != Handler_t::HandlerStatus_t::unconsumed) {
				return status;
			}
		}
		return Handler_t::HandlerStatus_t::unconsumed;
	}

	ParameterDB_t::ParameterDB_t() : current{} {}

	ParameterDB_t::IncrementTimeStepHelper_t ParameterDB_t::incrementInternalTimeStep() {
		std::lock_guard<std::mutex> lock(mtx);
		IncrementTimeStepHelper_t helper;

		helper.oldStep = current;
		current.internal_ticker += 1;
		helper.newStep = current;
		return helper;
	}

	TickerCode_t ParameterDB_t::getCurrentTimeStep() const {
		std::lock_guard<std::mutex> lock(mtx);
		return current;
	}

	ParameterDB_t::IncrementTimeStepHelper_t ParameterDB_t::incrementExternalTimeStep() {
		std::lock_guard<std::mutex> lock(mtx);
		IncrementTimeStepHelper_t helper;

		helper.oldStep = current;

		current.external_ticker += 1;
		current.internal_ticker = 0;

		helper.newStep = current;

		return helper;
	}

	void HandlerDB_t::addHandlerLogic(NGX_Strings::MacroStrings_enum_t key, Handler_t handler) {
		handlers.emplace(key, handler);
	}

	Handler_t::HandlerHelper HandlerDB_t::Apply(ParameterDB_t& db, CallEvent_t& event) {
		auto range = handlers.equal_range(event.key);
		for (auto it = range.first; it != range.second; ++it) {
			Handler_t::HandlerHelper status = it->second.ApplyFunc(db, event);
			if (status.status != Handler_t::HandlerStatus_t::unconsumed) {
				return status;
			}
		}
		return Handler_t::HandlerHelper{ Handler_t::HandlerStatus_t::unconsumed, 0 };
	}

	ParameterDB_t::ParameterDB_t() : current{} {
	}

	ParameterDB_t::IncrementTimeStepHelper_t ParameterDB_t::incrementInternalTimeStep() {
		std::lock_guard<std::mutex> lock(mtx);
		IncrementTimeStepHelper_t helper;

		helper.oldStep = current;

		current.internal_ticker += 1;

		helper.newStep = current;

		return helper;
	}

	TickerCode_t ParameterDB_t::getCurrentTimeStep() const {
		std::lock_guard<std::mutex> lock(mtx);
		return current;
	}

	ParameterDB_t::IncrementTimeStepHelper_t ParameterDB_t::incrementExternalTimeStep() {
		std::lock_guard<std::mutex> lock(mtx);
		IncrementTimeStepHelper_t helper;

		helper.oldStep = current;

		current.external_ticker += 1;
		current.internal_ticker = 0;

		helper.newStep = current;

		return helper;
	}

	void ParameterDB_t::Set(const char* name, const InputVariable_t value) {
		auto key = Parameter::stringToEnum(name);
		CallEvent_t event{ CallEvent_t::set, key, value, getCurrentTimeStep() };
		Handler_t::HandlerHelper result;

		{
			std::lock_guard<std::mutex> lock(mtx);

			result = handlers.Apply(*this, event);

			if (result.status == Handler_t::HandlerStatus_t::unconsumed) {
				value_current[key] = value;
				value_history.emplace(key, event);
			}
		}
	}

	InputVariable_t ParameterDB_t::Get(const char* name) {
		auto key = Parameter::stringToEnum(name);
		CallEvent_t event{ CallEvent_t::get, key, {}, getCurrentTimeStep() };
		Handler_t::HandlerHelper result;

		{
			std::lock_guard<std::mutex> lock(mtx);

			result = handlers.Apply(*this, event);

			if (result.status != Handler_t::HandlerStatus_t::unconsumed) {
				return event.value;
			}

			if (value_current.find(key) != value_current.end()) {
				return value_current[key];
			}
		}

		return 0;
	}


	void ParameterDB_t::addHandlerLogic(NGX_Strings::MacroStrings_enum_t key, Handler_t handler) {
		handlers.addHandlerLogic(key, handler);
	}

	void Parameter::Set(const char* InName, unsigned long long InValue) {
		parameterDB->Set(InName, InValue);
	}

	void Parameter::Set(const char* InName, float InValue) {
		parameterDB->Set(InName, InValue);
	}

	void Parameter::Set(const char* InName, double InValue) {
		parameterDB->Set(InName, InValue);
	}

	void Parameter::Set(const char* InName, unsigned int InValue) {
		parameterDB->Set(InName, InValue);
	}

	void Parameter::Set(const char* InName, int InValue) {
		parameterDB->Set(InName, InValue);
	}

	void Parameter::Set(const char* InName, ID3D11Resource* InValue) {
		parameterDB->Set(InName, InValue);
	}

	void Parameter::Set(const char* InName, ID3D12Resource* InValue) {
		parameterDB->Set(InName, InValue);
	}

	void Parameter::Set(const char* InName, void* InValue) {
		parameterDB->Set(InName, InValue);
	}

	void Parameter::Reset()
	{
		CyberLogArgs(this);
	}
	
	NGX_Strings::MacroStrings_enum_t Parameter::stringToEnum(const char* name) {
		return NGX_Strings::Strings_Converter.getEnumFromMacroName(name);
	}
}



// EvaluateRenderScale helper
inline FfxFsr2QualityMode DLSS2FSR2QualityTable(const NVSDK_NGX_PerfQuality_Value input)
{
	//CyberLogArgs(input);
	FfxFsr2QualityMode output;

	switch (input)
	{
	case NVSDK_NGX_PerfQuality_Value_UltraPerformance:
		output = FFX_FSR2_QUALITY_MODE_ULTRA_PERFORMANCE;
		break;
	case NVSDK_NGX_PerfQuality_Value_MaxPerf:
		output = FFX_FSR2_QUALITY_MODE_PERFORMANCE;
		break;
	case NVSDK_NGX_PerfQuality_Value_Balanced:
		output = FFX_FSR2_QUALITY_MODE_BALANCED;
		break;
	case NVSDK_NGX_PerfQuality_Value_MaxQuality:
		output = FFX_FSR2_QUALITY_MODE_QUALITY;
		break;
	case NVSDK_NGX_PerfQuality_Value_UltraQuality:
	default:
		output = (FfxFsr2QualityMode)5; //Set out-of-range value for non-existing fsr ultra quality mode
		break;
	}

	return output;
}

// EvaluateRenderScale helper
inline std::optional<float> GetQualityOverrideRatio(const NVSDK_NGX_PerfQuality_Value input, const std::shared_ptr<const Config> config)
{
	//CyberLogArgs(input);
	std::optional<float> output;

	if (!(config->QualityRatioOverrideEnabled.has_value() && config->QualityRatioOverrideEnabled.value()))
		return output; // override not enabled

	switch (input)
	{
	case NVSDK_NGX_PerfQuality_Value_UltraPerformance:
		output = config->QualityRatio_UltraPerformance;
		break;
	case NVSDK_NGX_PerfQuality_Value_MaxPerf:
		output = config->QualityRatio_Performance;
		break;
	case NVSDK_NGX_PerfQuality_Value_Balanced:
		output = config->QualityRatio_Balanced;
		break;
	case NVSDK_NGX_PerfQuality_Value_MaxQuality:
		output = config->QualityRatio_Quality;
		break;
	case NVSDK_NGX_PerfQuality_Value_UltraQuality:
		output = config->QualityRatio_UltraQuality;
		break;
	default:
		// no correlated value, add some logging?
		break;
	}
	return output;
}



/*
void Hyper_NGX_Parameter::EvaluateRenderScale()
{
	enum RenderScalePriorityPreference { ratio, resolution } priority = ratio;

	float scaleRatioX = 0;
	float scaleRatioY = 0;

	unsigned int finalResX = 0;
	unsigned int finalResY = 0;

	constexpr NVSDK_NGX_Dimensions supermin = { 160,90 };

	//CyberLogArgs();
	const std::shared_ptr<Config> config = CyberFsrContext::instance()->MyConfig;

	if (screenSize.Height == 0 || screenSize.Width == 0) {
		screenSize.Width = GetSystemMetrics(SM_CXSCREEN);
		screenSize.Height = GetSystemMetrics(SM_CYSCREEN);
	}

	if (windowSize.Height == 0 || windowSize.Width == 0) {
		windowSize.Width = screenSize.Width;
		windowSize.Height = screenSize.Height;
	}
	
	//RTXValue = 1;

	//Static Upscale Ratio Override
	if (config->UpscaleRatioOverrideEnabled.value_or(false) && config->UpscaleRatioOverrideValue.has_value()) {
		const auto value = config->UpscaleRatioOverrideValue.value();
		scaleRatioX = value;
		scaleRatioY = value;
	}
	else {
		float overrideRatio = GetQualityOverrideRatio(PerfQualityValue, config).value_or(0);
		if (overrideRatio != 0) {
			scaleRatioX = overrideRatio;
			scaleRatioY = overrideRatio;
		}
		else {
			const FfxFsr2QualityMode fsrQualityMode = DLSS2FSR2QualityTable(PerfQualityValue);

			if (fsrQualityMode < 5 && fsrQualityMode > 0) {
				ffxFsr2GetRenderResolutionFromQualityMode(&finalResX, &finalResY, windowSize.Width, windowSize.Height, fsrQualityMode);
			}
			else {
				finalResX = windowSize.Width;
				finalResY = windowSize.Height;
			}
		}
	}

	switch (priority) {
		case ratio: {
			if (scaleRatioX != 0 || scaleRatioY != 0) {
				SetRatio(scaleRatioX, scaleRatioY);
				break;
			}
			else 
				if (finalResX != 0 || finalResY != 0) {
				SetResolution(finalResX, finalResY);
				break;
			}
			else
				SetResolution(supermin.Width, supermin.Height);
			break;
		}
		case resolution: {
			if (finalResX != 0 || finalResY != 0) {
				SetResolution(finalResX, finalResY);
				break;
			}
			else 
				if (scaleRatioX != 0 || scaleRatioY != 0) {
				SetRatio(scaleRatioX, scaleRatioY);
				break;
			}
			else
				SetResolution(supermin.Width, supermin.Height);
			break;
	
		}
		default:
			SetResolution(supermin.Width, supermin.Height);
			break;
	}

	//renderSizeMin = supermin;
	renderSizeMin = renderSize;
	renderSizeMax = renderSize;
}

std::vector<NVSDK_NGX_Dimensions> generateResolutions(unsigned int maxWidth, unsigned int maxHeight, unsigned int ratioX, unsigned int ratioY) {
	CyberLogArgs(maxWidth, maxHeight, ratioX, ratioY);
	std::vector<NVSDK_NGX_Dimensions> resolutions;

	unsigned int factor = std::gcd(ratioX, ratioY);
	unsigned int ratioX1 = ratioX / factor;
	unsigned int ratioY1 = ratioY / factor;

	const unsigned int xIncrease = ratioX1;
	const unsigned int yIncrease = ratioY1;

	for (unsigned int w = ratioX1, h = ratioY1; w <= maxWidth && h <= maxHeight; w += xIncrease, h += yIncrease) {
		if (w % Hyper_NGX_Parameter::CLAMPING_VALUE == 0 && h % Hyper_NGX_Parameter::CLAMPING_VALUE == 0) {
			resolutions.push_back({ w, h });
			CyberLOGvi("Valid Resoltuion Calculated: ", w, h);
		}
	}

	return resolutions;
}

class ResolutionCache {
private:
	std::map<std::pair< long, long>, std::vector<NVSDK_NGX_Dimensions>> aspectRatioResolutions;

public:
	const std::vector<NVSDK_NGX_Dimensions>& getResolutions(long screenWidth, long screenHeight, long ratioX, long ratioY) {
		CyberLogArgs(screenWidth, screenHeight, ratioX, ratioY);


		long factor = std::gcd(ratioX, ratioY);
		long ratioX1 = ratioX / factor;
		long ratioY1 = ratioY / factor;

		std::pair<long, long> key = { ratioX1 , ratioY1 };

		auto needToGenerate = (aspectRatioResolutions.contains({ ratioX1, ratioY1}) == false);

		if (needToGenerate) {
			auto resList = generateResolutions(screenWidth * 2, screenHeight * 2, ratioX1, ratioY1);
			aspectRatioResolutions.emplace(key, resList);
		}

		return aspectRatioResolutions.at({ ratioX1, ratioY1 });
	}


};

ResolutionCache resolutionCache;

NVSDK_NGX_Dimensions findClosestResolution(const std::vector<NVSDK_NGX_Dimensions>& resolutions, long targetWidth, long targetHeight) {
	CyberLogArgs(targetWidth, targetHeight);
	NVSDK_NGX_Dimensions closestResolution = { 0, 0 };
	long minDifference = std::numeric_limits<long>::max();


	for (const auto& resolution : resolutions) {
		long inwidth = resolution.Width;
		long inheight = resolution.Height;

		long currentDifference = std::abs( targetWidth - inwidth) + std::abs( targetHeight - inheight);

		if (currentDifference < minDifference) {
			minDifference = currentDifference;
			closestResolution = resolution;
		}
	}

	return closestResolution;
}

void Hyper_NGX_Parameter::SetRatio(const float ScaleRatioX, float ScaleRatioY) {
	CyberLogArgs(ScaleRatioX, ScaleRatioY);
	long requestedWidth = windowSize.Width / ScaleRatioX;
	long requestedHeight = windowSize.Height / ScaleRatioY;

	// Calculate closest even resolutions
	long closestWidth = (requestedWidth % 2 == 0) ? requestedWidth : requestedWidth + 1;
	long closestHeight = (requestedHeight % 2 == 0) ? requestedHeight : requestedHeight + 1;

	// Update renderSize and scaleRatio with the closest even resolution
	renderSize.Width = closestWidth;
	renderSize.Height = closestHeight;
	scaleRatio.width = static_cast<float>(closestWidth) / windowSize.Width;
	scaleRatio.height = static_cast<float>(closestHeight) / windowSize.Height;
}

void Hyper_NGX_Parameter::SetResolution(const unsigned int width, const unsigned int height) {
	CyberLogArgs(width, height);

	long requestedWidth = width;
	long requestedHeight = height;

	// Calculate closest even resolutions
	long closestWidth = (requestedWidth % 2 == 0) ? requestedWidth : requestedWidth + 1;
	long closestHeight = (requestedHeight % 2 == 0) ? requestedHeight : requestedHeight + 1;

	// Update renderSize and scaleRatio with the closest even resolution
	renderSize.Width = closestWidth;
	renderSize.Height = closestHeight;
	scaleRatio.width = static_cast<float>(closestWidth) / windowSize.Width;
	scaleRatio.height = static_cast<float>(closestHeight) / windowSize.Height;
}

*/



NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetOptimalSettingsCallback(NVSDK_NGX_Parameter* InParams)
{
	/*
	static const int limit = 6;
	static int num = 6;
	*/

	CyberLogArgs(InParams);
	if (InParams != nullptr) {
		auto params = static_cast<Hyper_NGX::Parameter*>(InParams);
		return params->GetOptimalSettingsCallback();
	}

	/*
	if (num != 0) {
		float x = (float) ( (double) params->ratioUsed.width * (1.0 - (0.1 * num)) );
		float y = (float) ( (double) params->ratioUsed.height * (1.0 - (0.1 * num)) );
		params->SetRatio( x, y);
	}
	num = (num + 1) % limit;
	*/

	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetStatsCallback(NVSDK_NGX_Parameter* InParams)
{
	CyberLogArgs(InParams);

	//Somehow check for allocated memory
	//Then set values: SizeInBytes, OptLevel, IsDevSnippetBranch

	if (InParams != nullptr) {
		auto params = static_cast<Hyper_NGX::Parameter*>(InParams);
		return params->GetStatsCallback();
	}

	return NVSDK_NGX_Result_Success;
}