#include "pch.h"
#include "Config.h"
#include "CyberFsr.h"
#include "DirectXHooks.h"
#include "Util.h"

#define SaveToLog

#ifdef SaveToLog
#include <iostream>
#include <fstream>
#include <chrono>

// Declare a global ofstream object for writing to the log file
std::ofstream logFile;

// Declare a global mutex object for synchronization
std::mutex logMutex;

std::chrono::high_resolution_clock::time_point startTime = std::chrono::high_resolution_clock::now();

// Helper function to get the current CPU tick value relative to the starting time
unsigned long long getTick()
{
	auto currentTime = std::chrono::high_resolution_clock::now();
	return std::chrono::duration_cast<std::chrono::nanoseconds>(currentTime - startTime).count();
}

// Helper function to write the function name and CPU tick to the log file
void logFunctionCall(const std::string& functionName)
{
	std::lock_guard<std::mutex> lock(logMutex); // Lock the mutex

	// Open the log file if it is not already open
	if (!logFile.is_open())
	{
		logFile.open("debug.log", std::ios::app); // Open in append mode
	}

	if (logFile.is_open())
	{
		logFile << functionName << " " << getTick() << std::endl;
	}
}

// Helper macro to simplify logging function calls
#define LOG_FUNCTION_CALL() logFunctionCall(__func__)


#endif // SaveToLog


// dx 12 - > dx11 interop https://learn.microsoft.com/en-us/windows/win32/direct3d12/direct3d-12-with-direct3d-11--direct-2d-and-gdi

// external\FidelityFX-FSR2\src\ffx-fsr2-api\ffx_fsr2_interface.h
// external\nvngx_dlss_sdk\include\nvsdk_ngx_defs.h
// external\nvngx_dlss_sdk\include\nvsdk_ngx_helpers.h

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D11_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, NVSDK_NGX_Version InSDKVersion, const NVSDK_NGX_FeatureCommonInfo* APointer, const unsigned long long unknown)
{
#ifdef SaveToLog
	LOG_FUNCTION_CALL();
#endif // SaveToLog
	auto output = NVSDK_NGX_Result_Success;

	//CyberFSR::FeatureCommonInfo.LoggingInfo.LoggingCallback("Hello!", NVSDK_NGX_LOGGING_LEVEL_OFF, NVSDK_NGX_Feature_SuperSampling);

	return output;
}

//NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D11_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, NVSDK_NGX_Version InSDKVersion, const char* Apointer1, const char* Apointer2)
//{
//	// cyberpunk enters here
//	// cyberpunk id == 0x0000000005f83393
//
//	auto output = NVSDK_NGX_Result_Success;
//
//	//CyberFSR::FeatureCommonInfo.LoggingInfo.LoggingCallback("Hello!", NVSDK_NGX_LOGGING_LEVEL_OFF, NVSDK_NGX_Feature_SuperSampling);
//
//	return output;
//}

NVSDK_NGX_Result NVSDK_NGX_D3D11_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
#ifdef SaveToLog
	LOG_FUNCTION_CALL();
#endif // SaveToLog

	// InFeatureInfo has important info!!!?!
	auto output = NVSDK_NGX_Result_Success;

	return output;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D11_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
#ifdef SaveToLog
	LOG_FUNCTION_CALL();
#endif // SaveToLog

	// InFeatureInfo has important info!!!?!

	auto output = NVSDK_NGX_Result_Success;

	return output;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Shutdown(void)
{
#ifdef SaveToLog
	LOG_FUNCTION_CALL();
#endif // SaveToLog

	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Shutdown1(ID3D11Device* InDevice)
{
#ifdef SaveToLog
	LOG_FUNCTION_CALL();
#endif // SaveToLog

	return NVSDK_NGX_Result_Success;
}


// Nevertheless, due to the possibility that the user will be using an older driver
// version, NVSDK_NGX_GetParameters may still be used as a fallback if
// NVSDK_NGX_AllocateParameters
// or NVSDK_NGX_GetCapabilityParameters return NVSDK_NGX_Result_FAIL_OutOfDate.

// Parameter maps output by NVSDK_NGX_GetParameters are also pre-populated
// with NGX capabilities and available features.
// 
//Deprecated Parameter Function - Internal Memory Tracking
NVSDK_NGX_Result NVSDK_NGX_D3D11_GetParameters(NVSDK_NGX_Parameter** OutParameters)
{
#ifdef SaveToLog
	LOG_FUNCTION_CALL();
#endif // SaveToLog

	return NVSDK_NGX_Result_Success;
}

//TODO External Memory Tracking
NVSDK_NGX_Result NVSDK_NGX_D3D11_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters)
{
#ifdef SaveToLog
	LOG_FUNCTION_CALL();
#endif // SaveToLog

	return NVSDK_NGX_Result_Success;
}

//TODO
NVSDK_NGX_Result NVSDK_NGX_D3D11_AllocateParameters(NVSDK_NGX_Parameter** OutParameters)
{
#ifdef SaveToLog
	LOG_FUNCTION_CALL();
#endif // SaveToLog

	return NVSDK_NGX_Result_Success;
}

//TODO
NVSDK_NGX_Result NVSDK_NGX_D3D11_DestroyParameters(NVSDK_NGX_Parameter* InParameters)
{
#ifdef SaveToLog
	LOG_FUNCTION_CALL();
#endif // SaveToLog

	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId,
	const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes)
{
#ifdef SaveToLog
	LOG_FUNCTION_CALL();
#endif // SaveToLog

	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_CreateFeature(ID3D11DeviceContext* InDevCtx, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
#ifdef SaveToLog
	LOG_FUNCTION_CALL();
#endif // SaveToLog

	NVSDK_NGX_Result output = NVSDK_NGX_Result_Fail;

	return output;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_ReleaseFeature(NVSDK_NGX_Handle* InHandle)
{
#ifdef SaveToLog
	LOG_FUNCTION_CALL();
#endif // SaveToLog

	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_EvaluateFeature(ID3D11DeviceContext* InDevCtx, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
#ifdef SaveToLog
	LOG_FUNCTION_CALL();
#endif // SaveToLog

	return NVSDK_NGX_Result_Success;
}
