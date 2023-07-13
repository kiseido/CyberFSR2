#include "pch.h"
#ifndef DX11_INTERPOSER_H
#define DX11_INTERPOSER_H

#include "Interposer.h"

namespace CyberInterposer
{
    class DX11Interposer : public GInterposer
    {
    public:
        NVSDK_NGX_Result Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion) override;
        NVSDK_NGX_Result Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion, unsigned long long InFlags) override;
        NVSDK_NGX_Result Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion) override;
        NVSDK_NGX_Result Shutdown() override;
        NVSDK_NGX_Result GetParameters(NVSDK_NGX_Parameter** OutParameters) override;
        NVSDK_NGX_Result GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId, const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes) override;
        NVSDK_NGX_Result CreateFeature(ID3D11Device* InDevice, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle) override;
        NVSDK_NGX_Result ReleaseFeature(NVSDK_NGX_Handle* InHandle) override;
        NVSDK_NGX_Result EvaluateFeature(ID3D11DeviceContext* InDeviceContext, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback) override;
    };
} // namespace CyberInterposer

#endif
