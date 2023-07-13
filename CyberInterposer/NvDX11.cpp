#include "pch.h"
#include "NvCommon.h"
#include "Interposer.h"
#include "Logger.h"

using namespace CyberInterposer;



NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	CyberLOG();
	if (function_table.pfn_D3D11_Init != nullptr)
		return function_table.pfn_D3D11_Init(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);

	return NVSDK_NGX_Result_Fail;
}


NVSDK_NGX_Result NVSDK_NGX_D3D11_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath,
	ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion,
	unsigned long long unknown0)
{
	CyberLOG();

	if (function_table.pfn_D3D11_Init_Ext != nullptr)
	{
		return function_table.pfn_D3D11_Init_Ext(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, unknown0);
	}

	return NVSDK_NGX_Result_Fail;
}



NVSDK_NGX_Result NVSDK_NGX_D3D11_Shutdown(void)
{
	CyberLOG();

	if (function_table.pfn_D3D11_Shutdown != nullptr)
	{
		return function_table.pfn_D3D11_Shutdown();
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_GetParameters(NVSDK_NGX_Parameter** OutParameters)
{
	CyberLOG();
	if (function_table.pfn_D3D11_GetParameters != nullptr)
	{
		return function_table.pfn_D3D11_GetParameters(OutParameters);
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId, const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes)
{
	CyberLOG();
	if (function_table.pfn_D3D11_GetScratchBufferSize != nullptr)
	{
		return function_table.pfn_D3D11_GetScratchBufferSize(InFeatureId, InParameters, OutSizeInBytes);
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_CreateFeature(ID3D11Device* InDevice, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
	CyberLOG();
	if (function_table.pfn_D3D11_CreateFeature != nullptr)
	{
		return function_table.pfn_D3D11_CreateFeature(InDevice, InFeatureID, InParameters, OutHandle);
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_ReleaseFeature(NVSDK_NGX_Handle* InHandle)
{
	CyberLOG();
	if (function_table.pfn_D3D11_ReleaseFeature != nullptr)
	{
		return function_table.pfn_D3D11_ReleaseFeature(InHandle);
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_EvaluateFeature(ID3D11Device* InDevice, NVSDK_NGX_Handle* InDeviceContext, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
	CyberLOG();
	if (function_table.pfn_D3D11_EvaluateFeature != nullptr)
	{
		return function_table.pfn_D3D11_EvaluateFeature(InDevice, InDeviceContext, InFeatureHandle, InParameters, InCallback);
	}

	return NVSDK_NGX_Result_Fail;
}


NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D11_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	CyberLOG();

	if (function_table.pfn_D3D11_Init_ProjectID != nullptr)
	{
		return function_table.pfn_D3D11_Init_ProjectID(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);
	}
	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Shutdown1(ID3D11Device* InDevice)
{
	CyberLOG();
	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Fail;
}


NVSDK_NGX_Result NVSDK_NGX_D3D11_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters)
{
	CyberLOG();
	if (function_table.pfn_D3D11_GetCapabilityParameters != nullptr)
	{
		return function_table.pfn_D3D11_GetCapabilityParameters(OutParameters);
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_AllocateParameters(NVSDK_NGX_Parameter** OutParameters)
{
	CyberLOG();
	if (function_table.pfn_D3D11_AllocateParameters != nullptr)
	{
		return function_table.pfn_D3D11_AllocateParameters(OutParameters);
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_DestroyParameters(NVSDK_NGX_Parameter* InParameters)
{
	CyberLOG();
	if (function_table.pfn_D3D11_DestroyParameters != nullptr)
	{
		return function_table.pfn_D3D11_DestroyParameters(InParameters);
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_CreateFeature(ID3D11DeviceContext* InDevCtx, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
	CyberLOG();
	if (function_table.pfn_D3D11_CreateFeature != nullptr)
	{
		return function_table.pfn_D3D11_CreateFeature(InDevCtx, InFeatureID, InParameters, OutHandle);
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_EvaluateFeature(ID3D11DeviceContext* InDevCtx, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
	CyberLOG();
	if (function_table.pfn_D3D11_EvaluateFeature != nullptr)
	{
		return function_table.pfn_D3D11_EvaluateFeature(InDevCtx, InFeatureHandle, InParameters, InCallback);
	}

	return NVSDK_NGX_Result_Fail;
}