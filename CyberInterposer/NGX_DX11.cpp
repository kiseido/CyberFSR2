#include "pch.h"
#include "NGX_Interposer.h"


#ifdef CyberInterposer_DO_DX11


namespace CyberInterposer {

	bool PFN_Table_NVNGX_DX11::LoadDLL(HMODULE hModule, bool populateChildren)
	{
		CyberLogArgs(hModule, populateChildren);

		if (hModule == nullptr)
		{
			return false;
		}

		bool foundFunctions = true;

		foundFunctions &= LoadFunction(pfn_D3D11_Init, hModule, "NVSDK_NGX_D3D11_Init");
		foundFunctions &= LoadFunction(pfn_D3D11_Init_Ext, hModule, "NVSDK_NGX_D3D11_Init_Ext");
		foundFunctions &= LoadFunction(pfn_D3D11_Init_ProjectID, hModule, "NVSDK_NGX_D3D11_Init_ProjectID");
		foundFunctions &= LoadFunction(pfn_D3D11_Shutdown, hModule, "NVSDK_NGX_D3D11_Shutdown");
		foundFunctions &= LoadFunction(pfn_D3D11_Shutdown1, hModule, "NVSDK_NGX_D3D11_Shutdown1");
		foundFunctions &= LoadFunction(pfn_D3D11_GetCapabilityParameters, hModule, "NVSDK_NGX_D3D11_GetCapabilityParameters");
		foundFunctions &= LoadFunction(pfn_D3D11_GetParameters, hModule, "NVSDK_NGX_D3D11_GetParameters");
		foundFunctions &= LoadFunction(pfn_D3D11_GetScratchBufferSize, hModule, "NVSDK_NGX_D3D11_GetScratchBufferSize");
		foundFunctions &= LoadFunction(pfn_D3D11_CreateFeature, hModule, "NVSDK_NGX_D3D11_CreateFeature");
		foundFunctions &= LoadFunction(pfn_D3D11_ReleaseFeature, hModule, "NVSDK_NGX_D3D11_ReleaseFeature");
		foundFunctions &= LoadFunction(pfn_D3D11_EvaluateFeature, hModule, "NVSDK_NGX_D3D11_EvaluateFeature");
		foundFunctions &= LoadFunction(pfn_D3D11_EvaluateFeature_C, hModule, "NVSDK_NGX_D3D11_EvaluateFeature_C");
		foundFunctions &= LoadFunction(pfn_D3D11_AllocateParameters, hModule, "NVSDK_NGX_D3D11_AllocateParameters");
		foundFunctions &= LoadFunction(pfn_D3D11_DestroyParameters, hModule, "NVSDK_NGX_D3D11_DestroyParameters");

		return foundFunctions;
	}

}



Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_D3D11_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, start);

	const auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_Init;

	if (ptr != nullptr) {
		auto result = ptr(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);
		CyberLOGvi("NVSDK_NGX_D3D11_Init", result);
		return result;
	}

	CyberLOGvi("NVSDK_NGX_D3D11_Init: pfn_D3D11_Init is nullptr");
	return NVSDK_NGX_Result_Fail;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_D3D11_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath,
	ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion,
	unsigned long long unknown0)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, unknown0, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_Init_Ext;

	if (ptr != nullptr)
	{
		auto result = ptr(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, unknown0);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}



Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_D3D11_Shutdown(void)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_Shutdown;

	if (ptr != nullptr)
	{
		auto result = ptr();
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_D3D11_GetParameters(NVSDK_NGX_Parameter** OutParameters)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(OutParameters, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_GetParameters;

	if (ptr != nullptr)
	{
		CyberInterposer::CI_Parameter* internalParam = CyberInterposer::CI_MGX_Parameter_StaticAlloc::GetParameters_depreciated.claim();
		NVSDK_NGX_Result result = ptr(OutParameters);
		internalParam->wrapped = *OutParameters;
		*OutParameters = internalParam;
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_D3D11_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId, const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InFeatureId, InParameters, OutSizeInBytes, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_GetScratchBufferSize;

	if (ptr != nullptr)
	{
		auto result = ptr(InFeatureId, InParameters, OutSizeInBytes);
		CyberLOGvi(result, *OutSizeInBytes);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_D3D11_CreateFeature(ID3D11DeviceContext *InDevCtx, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter *InParameters, NVSDK_NGX_Handle **OutHandle)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InDevCtx, InFeatureID, InParameters, OutHandle, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_CreateFeature;

	if (ptr != nullptr)
	{
		auto result = ptr(InDevCtx, InFeatureID, InParameters, OutHandle);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_D3D11_ReleaseFeature(NVSDK_NGX_Handle* InHandle)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InHandle, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_ReleaseFeature;

	if (ptr != nullptr)
	{
		auto result = ptr(InHandle);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_D3D11_EvaluateFeature(ID3D11DeviceContext* InDevCtx, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InDevCtx, InFeatureHandle, InParameters, InCallback, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_EvaluateFeature;

	if (ptr != nullptr)
	{
		auto result = ptr(InDevCtx, InFeatureHandle, InParameters, InCallback);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_D3D11_EvaluateFeature_C(ID3D11DeviceContext* InDevCtx, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback_C InCallback)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InDevCtx, InFeatureHandle, InParameters, InCallback, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_EvaluateFeature_C;

	if (ptr != nullptr)
	{
		auto result = ptr(InDevCtx, InFeatureHandle, InParameters, InCallback);
		CyberLOGvi(result);
		return result;
	}
	return NVSDK_NGX_Result_Fail;
}


Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_D3D11_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_Init_ProjectID;

	if (ptr != nullptr)
	{
		auto result = ptr(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_D3D11_Shutdown1(ID3D11Device* InDevice)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InDevice, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_Shutdown1;

	if (ptr != nullptr)
	{
		auto result = ptr(InDevice);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}


Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_D3D11_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(OutParameters, start);

	const auto& ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_GetCapabilityParameters;

	if (ptr != nullptr)
	{
		CyberInterposer::CI_Parameter* internalParam = CyberInterposer::CI_MGX_Parameter_StaticAlloc::AllocateParameters.claim();
		NVSDK_NGX_Parameter** interim = OutParameters;
		NVSDK_NGX_Result result = ptr(interim);
		internalParam->wrapped.param = *interim;

		*OutParameters = internalParam;

		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_D3D11_AllocateParameters(NVSDK_NGX_Parameter** OutParameters)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(OutParameters, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_AllocateParameters;

	if (ptr != nullptr)
	{
		CyberInterposer::CI_Parameter* internalParam = CyberInterposer::CI_MGX_Parameter_StaticAlloc::AllocateParameters.claim();
		NVSDK_NGX_Result result = ptr(OutParameters);
		internalParam->wrapped.param = *OutParameters;
		*OutParameters = internalParam;
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

Expose_API NVSDK_NGX_Result C_Declare NVSDK_NGX_D3D11_DestroyParameters(NVSDK_NGX_Parameter* InParameters)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InParameters, start);

	auto ptr = CyberInterposer::DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_DestroyParameters;

	if (ptr != nullptr)
	{
		CyberInterposer::CI_Parameter* internalParam = static_cast<CyberInterposer::CI_Parameter*>(InParameters);

		NVSDK_NGX_Result result = ptr(internalParam->wrapped.param);

		// Release the parameter from custom allocator.
		CyberInterposer::CI_MGX_Parameter_StaticAlloc::AllocateParameters.release(internalParam);

		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

#endif