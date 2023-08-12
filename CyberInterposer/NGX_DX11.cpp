#include "pch.h"
#include "NGX_Interposer.h"


#ifdef CyberInterposer_DO_DX11

using namespace CyberInterposer;

bool CyberInterposer::PFN_Table_NVNGX_DX11::LoadDLL(HMODULE hModule, bool populateChildren)
{
	CyberLogArgs(hModule, populateChildren);

	if (hModule == nullptr)
	{
		return false;
	}

	pfn_D3D11_Init = reinterpret_cast<PFN_NVSDK_NGX_D3D11_Init>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_Init"));
	pfn_D3D11_Init_Ext = reinterpret_cast<PFN_NVSDK_NGX_D3D11_Init_Ext>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_Init_Ext"));
	pfn_D3D11_Init_ProjectID = reinterpret_cast<PFN_NVSDK_NGX_D3D11_Init_ProjectID>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_Init_ProjectID"));

	pfn_D3D11_Shutdown = reinterpret_cast<PFN_NVSDK_NGX_D3D11_Shutdown>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_Shutdown"));
	pfn_D3D11_Shutdown1 = reinterpret_cast<PFN_NVSDK_NGX_D3D11_Shutdown1>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_Shutdown1"));

	pfn_D3D11_GetCapabilityParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D11_GetCapabilityParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_GetCapabilityParameters"));
	pfn_D3D11_GetParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D11_GetParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_GetParameters"));

	pfn_D3D11_GetScratchBufferSize = reinterpret_cast<PFN_NVSDK_NGX_D3D11_GetScratchBufferSize>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_GetScratchBufferSize"));

	pfn_D3D11_CreateFeature = reinterpret_cast<PFN_NVSDK_NGX_D3D11_CreateFeature>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_CreateFeature"));
	pfn_D3D11_ReleaseFeature = reinterpret_cast<PFN_NVSDK_NGX_D3D11_ReleaseFeature>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_ReleaseFeature"));
	pfn_D3D11_EvaluateFeature = reinterpret_cast<PFN_NVSDK_NGX_D3D11_EvaluateFeature>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_EvaluateFeature"));
	pfn_D3D11_EvaluateFeature_C = reinterpret_cast<PFN_NVSDK_NGX_D3D11_EvaluateFeature_C>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_EvaluateFeature_C"));

	pfn_D3D11_AllocateParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D11_AllocateParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_AllocateParameters"));
	pfn_D3D11_DestroyParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D11_DestroyParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_DestroyParameters"));

	bool foundFunctions = true;

#define CyDLLLoadLog(name) \
	do { \
		const bool found = (name != nullptr); \
		if(found){ \
			CyberLOGi(#name, " found", name); \
		} \
		else { \
			CyberLOGi(#name, " not found"); \
		} \
		foundFunctions = false; \
	} while(false)

	CyDLLLoadLog(pfn_D3D11_Init);
	CyDLLLoadLog(pfn_D3D11_Init_Ext);
	CyDLLLoadLog(pfn_D3D11_Init_ProjectID);
	CyDLLLoadLog(pfn_D3D11_Shutdown);
	CyDLLLoadLog(pfn_D3D11_Shutdown1);
	CyDLLLoadLog(pfn_D3D11_GetCapabilityParameters);
	CyDLLLoadLog(pfn_D3D11_GetParameters);
	CyDLLLoadLog(pfn_D3D11_GetScratchBufferSize);
	CyDLLLoadLog(pfn_D3D11_CreateFeature);
	CyDLLLoadLog(pfn_D3D11_ReleaseFeature);
	CyDLLLoadLog(pfn_D3D11_EvaluateFeature);
	CyDLLLoadLog(pfn_D3D11_EvaluateFeature_C);
	CyDLLLoadLog(pfn_D3D11_AllocateParameters);
	CyDLLLoadLog(pfn_D3D11_DestroyParameters);

#undef CyDLLLoadLog

	return foundFunctions;
}


NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, start);

	const auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_Init;

	if (ptr != nullptr) {
		auto result = ptr(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);
		CyberLOGvi("NVSDK_NGX_D3D11_Init", result);
		return result;
	}

	CyberLOGvi("NVSDK_NGX_D3D11_Init: pfn_D3D11_Init is nullptr");
	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath,
	ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion,
	unsigned long long unknown0)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, unknown0, start);

	auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_Init_Ext;

	if (ptr != nullptr)
	{
		auto result = ptr(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, unknown0);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}



NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Shutdown(void)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(start);

	auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_Shutdown;

	if (ptr != nullptr)
	{
		auto result = ptr();
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_GetParameters(NVSDK_NGX_Parameter** OutParameters)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(OutParameters, start);

	auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_GetParameters;

	if (ptr != nullptr)
	{
		CyberInterposer::CI_NGX_Parameter* internalParam = CI_MGX_Parameter_StaticAlloc::GetParameters_depreciated.claim();
		NVSDK_NGX_Result result = ptr(OutParameters);
		internalParam->wrapped = *OutParameters;
		*OutParameters = internalParam;
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId, const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InFeatureId, InParameters, OutSizeInBytes, start);

	auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_GetScratchBufferSize;

	if (ptr != nullptr)
	{
		auto result = ptr(InFeatureId, InParameters, OutSizeInBytes);
		CyberLOGvi(result, *OutSizeInBytes);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_CreateFeature(ID3D11DeviceContext *InDevCtx, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter *InParameters, NVSDK_NGX_Handle **OutHandle)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InDevCtx, InFeatureID, InParameters, OutHandle, start);

	auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_CreateFeature;

	if (ptr != nullptr)
	{
		auto result = ptr(InDevCtx, InFeatureID, InParameters, OutHandle);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_ReleaseFeature(NVSDK_NGX_Handle* InHandle)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InHandle, start);

	auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_ReleaseFeature;

	if (ptr != nullptr)
	{
		auto result = ptr(InHandle);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_EvaluateFeature(ID3D11DeviceContext* InDevCtx, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InDevCtx, InFeatureHandle, InParameters, InCallback, start);

	auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_EvaluateFeature;

	if (ptr != nullptr)
	{
		auto result = ptr(InDevCtx, InFeatureHandle, InParameters, InCallback);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_EvaluateFeature_C(ID3D11DeviceContext* InDevCtx, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback_C InCallback)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InDevCtx, InFeatureHandle, InParameters, InCallback, start);

	auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_EvaluateFeature_C;

	if (ptr != nullptr)
	{
		auto result = ptr(InDevCtx, InFeatureHandle, InParameters, InCallback);
		CyberLOGvi(result);
		return result;
	}
	return NVSDK_NGX_Result_Fail;
}


NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, start);

	auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_Init_ProjectID;

	if (ptr != nullptr)
	{
		auto result = ptr(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Shutdown1(ID3D11Device* InDevice)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InDevice, start);

	auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_Shutdown1;

	if (ptr != nullptr)
	{
		auto result = ptr(InDevice);
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}


NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(OutParameters, start);

	const auto& ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_GetCapabilityParameters;

	if (ptr != nullptr)
	{
		CyberInterposer::CI_NGX_Parameter* internalParam = CI_MGX_Parameter_StaticAlloc::AllocateParameters.claim();
		NVSDK_NGX_Parameter** interim = OutParameters;
		NVSDK_NGX_Result result = ptr(interim);
		internalParam->wrapped.param = *interim;

		*OutParameters = internalParam;

		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_AllocateParameters(NVSDK_NGX_Parameter** OutParameters)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(OutParameters, start);

	auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_AllocateParameters;

	if (ptr != nullptr)
	{
		CyberInterposer::CI_NGX_Parameter* internalParam = CI_MGX_Parameter_StaticAlloc::AllocateParameters.claim();
		NVSDK_NGX_Result result = ptr(OutParameters);
		internalParam->wrapped.param = *OutParameters;
		*OutParameters = internalParam;
		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_DestroyParameters(NVSDK_NGX_Parameter* InParameters)
{
	const CyberTypes::RTC start = CyberTypes::RTC(true);
	WaitForLoading();
	CyberLogArgs(InParameters, start);

	auto ptr = DLLs.GetLoadedDLL().pointer_tables.PFN_DX11.pfn_D3D11_DestroyParameters;

	if (ptr != nullptr)
	{
		CyberInterposer::CI_NGX_Parameter* internalParam = static_cast<CyberInterposer::CI_NGX_Parameter*>(InParameters);

		NVSDK_NGX_Result result = ptr(internalParam->wrapped.param);

		// Release the parameter from custom allocator.
		CI_MGX_Parameter_StaticAlloc::AllocateParameters.release(internalParam);

		CyberLOGvi(result);
		return result;
	}

	return NVSDK_NGX_Result_Fail;
}

#endif