#include "pch.h"

#ifndef CyInt_DX11_INTERPOSER_H
#define CyInt_DX11_INTERPOSER_H

#include "Common.h"

//#include "Config.h"
//#include "DirectXHooks.h"
//#include "Util.h"

#include <d3d11.h>
#include <d3dcompiler.h>

#include "CI_Logging.h"

namespace CyberInterposer
{
    struct PFN_Table_NVNGX_DX11 : public  PFN_Table_T {
        PFN_NVSDK_NGX_Parameter_GetD3d11Resource pfn_GetD3d11Resource = nullptr;
        PFN_NVSDK_NGX_Parameter_SetD3d11Resource pfn_SetD3d11Resource = nullptr;

        PFN_NVSDK_NGX_D3D11_Init pfn_D3D11_Init = nullptr;
        PFN_NVSDK_NGX_D3D11_Init_Ext pfn_D3D11_Init_Ext = nullptr;
        PFN_NVSDK_NGX_D3D11_Init_ProjectID pfn_D3D11_Init_ProjectID = nullptr;

        PFN_NVSDK_NGX_D3D11_Shutdown pfn_D3D11_Shutdown = nullptr;
        PFN_NVSDK_NGX_D3D11_Shutdown1 pfn_D3D11_Shutdown1 = nullptr;

        PFN_NVSDK_NGX_D3D11_GetCapabilityParameters pfn_D3D11_GetCapabilityParameters = nullptr;
        PFN_NVSDK_NGX_D3D11_GetParameters pfn_D3D11_GetParameters = nullptr;

        PFN_NVSDK_NGX_D3D11_GetScratchBufferSize pfn_D3D11_GetScratchBufferSize = nullptr;

        PFN_NVSDK_NGX_D3D11_CreateFeature pfn_D3D11_CreateFeature = nullptr;
        PFN_NVSDK_NGX_D3D11_ReleaseFeature pfn_D3D11_ReleaseFeature = nullptr;
        PFN_NVSDK_NGX_D3D11_EvaluateFeature pfn_D3D11_EvaluateFeature = nullptr;
        PFN_NVSDK_NGX_D3D11_EvaluateFeature_C pfn_D3D11_EvaluateFeature_C = nullptr;

        PFN_NVSDK_NGX_D3D11_AllocateParameters pfn_D3D11_AllocateParameters = nullptr;
        PFN_NVSDK_NGX_D3D11_DestroyParameters pfn_D3D11_DestroyParameters = nullptr;

        bool LoadDLL(HMODULE inputFile, bool populateChildren) override;
    };
}

void NVSDK_CONV NVSDK_NGX_Parameter_SetD3d11Resource(NVSDK_NGX_Parameter* InParameter, const char* InName, ID3D11Resource* InValue);
NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_Parameter_GetD3d11Resource(NVSDK_NGX_Parameter* InParameter, const char* InName, ID3D11Resource** OutValue);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion, unsigned long long InFlags);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, NVSDK_NGX_Version InSDKVersion, const char* Apointer1, const char* Apointer2);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion);


NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Shutdown(void);
NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Shutdown1(ID3D11Device* InDevice);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters);
NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_GetParameters(NVSDK_NGX_Parameter** OutParameters);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId, const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_CreateFeature(ID3D11Device* InDevice, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle);
NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_CreateFeature(ID3D11DeviceContext* InDevCtx, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_ReleaseFeature(NVSDK_NGX_Handle* InHandle);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_EvaluateFeature(ID3D11Device* InDevice, ID3D11DeviceContext* InDeviceContext, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback);
NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_EvaluateFeature(ID3D11DeviceContext* InDevCtx, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback);
NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_EvaluateFeature_C(ID3D11DeviceContext* InDevCtx, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback_C InCallback);

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_AllocateParameters(NVSDK_NGX_Parameter** OutParameters);
NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_DestroyParameters(NVSDK_NGX_Parameter* InParameters);

// external\FidelityFX-FSR2\src\ffx-fsr2-api\ffx_fsr2_interface.h
// external\nvngx_dlss_sdk\include\nvsdk_ngx_defs.h
// external\nvngx_dlss_sdk\include\nvsdk_ngx_helpers.h




#endif
