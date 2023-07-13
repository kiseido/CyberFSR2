#include "pch.h"
#include "NvCommon.h"
#include "Interposer.h"
#include "Logger.h"

using namespace Interposer;



NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	CyberLOG();
	if (pfn_D3D11_Init != nullptr)
		return pfn_D3D11_Init(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);

	return NVSDK_NGX_Result_Fail;
}


NVSDK_NGX_Result NVSDK_NGX_D3D11_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath,
	ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion,
	unsigned long long unknown0)
{
	CyberLOG();
	typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_Init_Ext)(unsigned long long, const wchar_t*, ID3D11Device*, const NVSDK_NGX_FeatureCommonInfo*, NVSDK_NGX_Version, unsigned long long);
	PFN_NVSDK_NGX_D3D11_Init_Ext pfn_D3D11_Init_Ext = reinterpret_cast<PFN_NVSDK_NGX_D3D11_Init_Ext>(pfn_SetVoidPointer);  // Assuming pfn_SetVoidPointer holds the function pointer
	if (pfn_D3D11_Init_Ext != nullptr)
	{
		return pfn_D3D11_Init_Ext(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, unknown0);
	}

	return NVSDK_NGX_Result_Fail;
}



NVSDK_NGX_Result NVSDK_NGX_D3D11_Shutdown(void)
{
	CyberLOG();
	// is pointer good? cast pointer and call it and return any results!
	typedef NVSDK_NGX_Result(NVSDK_CONV* PFN_NVSDK_NGX_D3D11_Shutdown)(void);
	PFN_NVSDK_NGX_D3D11_Shutdown pfn_D3D11_Shutdown = reinterpret_cast<PFN_NVSDK_NGX_D3D11_Shutdown>(pfn_GetVoidPointer);  // Assuming pfn_GetVoidPointer holds the function pointer
	if (pfn_D3D11_Shutdown != nullptr)
	{
		return pfn_D3D11_Shutdown();
	}

	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_GetParameters(NVSDK_NGX_Parameter** OutParameters)
{
	CyberLOG();
	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId, const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes)
{
	CyberLOG();
	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_CreateFeature(ID3D11Device* InDevice, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
	CyberLOG();
	// is pointer good? cast pointer and call it and return any results!

	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_ReleaseFeature(NVSDK_NGX_Handle* InHandle)
{
	CyberLOG();
	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_EvaluateFeature(ID3D11Device* InDevice, ID3D11DeviceContext* InDeviceContext, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
	CyberLOG();
	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}



NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D11_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	CyberLOG();
	auto output = NVSDK_NGX_Result_Success;
	// is pointer good? cast pointer and call it and return any results!
	return output;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Shutdown1(ID3D11Device* InDevice)
{
	CyberLOG();
	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}


//TODO External Memory Tracking
NVSDK_NGX_Result NVSDK_NGX_D3D11_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters)
{
	CyberLOG();
	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

//TODO
NVSDK_NGX_Result NVSDK_NGX_D3D11_AllocateParameters(NVSDK_NGX_Parameter** OutParameters)
{
	CyberLOG();
	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

//TODO
NVSDK_NGX_Result NVSDK_NGX_D3D11_DestroyParameters(NVSDK_NGX_Parameter* InParameters)
{
	CyberLOG();
	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_CreateFeature(ID3D11DeviceContext* InDevCtx, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
	CyberLOG();

	NVSDK_NGX_Result output = NVSDK_NGX_Result_Fail;
	// is pointer good? cast pointer and call it and return any results!
	return output;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_EvaluateFeature(ID3D11DeviceContext* InDevCtx, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
	CyberLOG();
	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}
