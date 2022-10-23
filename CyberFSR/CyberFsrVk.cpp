#include "pch.h"
#include "Config.h"
#include "CyberFsr.h"
#include "DirectXHooks.h"
#include "Util.h"

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_VULKAN_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, VkInstance InInstance, VkPhysicalDevice InPD, VkDevice InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	CyberFsrContext::instance()->VulkanDevice = InDevice;
	CyberFsrContext::instance()->VulkanInstance = InInstance;
	CyberFsrContext::instance()->VulkanPhysicalDevice = InPD;
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_VULKAN_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, VkInstance InInstance, VkPhysicalDevice InPD, VkDevice InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	return NVSDK_NGX_VULKAN_Init(0x1337, InApplicationDataPath, InInstance, InPD, InDevice, InFeatureInfo, InSDKVersion);
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_VULKAN_Init_with_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, VkInstance InInstance, VkPhysicalDevice InPD, VkDevice InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	return NVSDK_NGX_VULKAN_Init(0x1337, InApplicationDataPath, InInstance, InPD, InDevice, InFeatureInfo, InSDKVersion);
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_Shutdown(void)
{
	CyberFsrContext::instance()->VulkanDevice = nullptr;
	CyberFsrContext::instance()->VulkanInstance = nullptr;
	CyberFsrContext::instance()->VulkanPhysicalDevice = nullptr;
	CyberFsrContext::instance()->Parameters.clear();
	CyberFsrContext::instance()->Contexts.clear();
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_Shutdown1(VkDevice InDevice)
{
	CyberFsrContext::instance()->VulkanDevice = nullptr;
	CyberFsrContext::instance()->VulkanInstance = nullptr;
	CyberFsrContext::instance()->VulkanPhysicalDevice = nullptr;
	CyberFsrContext::instance()->Parameters.clear();
	CyberFsrContext::instance()->Contexts.clear();
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_VULKAN_GetParameters(NVSDK_NGX_Parameter** OutParameters)
{
	*OutParameters = CyberFsrContext::instance()->AllocateParameter();
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_AllocateParameters(NVSDK_NGX_Parameter** OutParameters)
{
	*OutParameters = new NvParameter();
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters)
{
	*OutParameters = new NvParameter();
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_DestroyParameters(NVSDK_NGX_Parameter* InParameters)
{
	delete InParameters;
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId, const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes)
{
	auto instance = CyberFsrContext::instance();
	*OutSizeInBytes = ffxFsr2GetScratchMemorySizeVK(instance->VulkanPhysicalDevice);
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_CreateFeature(VkCommandBuffer InCmdBuffer, NVSDK_NGX_Feature InFeatureID, const NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
	return NVSDK_NGX_VULKAN_CreateFeature1(CyberFsrContext::instance()->VulkanDevice, InCmdBuffer, InFeatureID, InParameters, OutHandle);
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_CreateFeature1(VkDevice InDevice, VkCommandBuffer InCmdList, NVSDK_NGX_Feature InFeatureID, const NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
 	const auto inParams = dynamic_cast<const NvParameter*>(InParameters);

	auto instance = CyberFsrContext::instance();
	auto& config = instance->MyConfig;
	auto deviceContext = instance->CreateContext();
	deviceContext->ViewMatrix = ViewMatrixHook::Create(*config);
#ifdef _DEBUG
	deviceContext->DebugLayer = std::make_unique<DebugOverlay>(InDevice, InCmdList);
#endif

	*OutHandle = &deviceContext->Handle;

	auto initParams = deviceContext->FsrContextDescription;

	const size_t scratchBufferSize = ffxFsr2GetScratchMemorySizeVK(instance->VulkanPhysicalDevice);
	deviceContext->ScratchBuffer = std::vector<unsigned char>(scratchBufferSize);
	auto scratchBuffer = deviceContext->ScratchBuffer.data();

	FfxErrorCode errorCode = ffxFsr2GetInterfaceVK(&initParams.callbacks, scratchBuffer, scratchBufferSize, instance->VulkanPhysicalDevice, vkGetDeviceProcAddr);
	FFX_ASSERT(errorCode == FFX_OK);

	initParams.device = ffxGetDeviceVK(InDevice);
	initParams.maxRenderSize.width = inParams->Width;
	initParams.maxRenderSize.height = inParams->Height;
	initParams.displaySize.width = inParams->OutWidth;
	initParams.displaySize.height = inParams->OutHeight;
	initParams.flags = (inParams->DepthInverted) ? FFX_FSR2_ENABLE_DEPTH_INVERTED : 0
		| (inParams->AutoExposure) ? FFX_FSR2_ENABLE_AUTO_EXPOSURE : 0
		| (inParams->Hdr) ? FFX_FSR2_ENABLE_HIGH_DYNAMIC_RANGE : 0
		| (inParams->JitterMotion) ? FFX_FSR2_ENABLE_MOTION_VECTORS_JITTER_CANCELLATION : 0
		| (!inParams->LowRes) ? FFX_FSR2_ENABLE_DISPLAY_RESOLUTION_MOTION_VECTORS : 0;

	initParams.flags = 0;
	if (config->DepthInverted.value_or(inParams->DepthInverted))
	{
		initParams.flags |= FFX_FSR2_ENABLE_DEPTH_INVERTED;
	}
	if (config->AutoExposure.value_or(inParams->AutoExposure))
	{
		initParams.flags |= FFX_FSR2_ENABLE_AUTO_EXPOSURE;
	}
	if (config->HDR.value_or(inParams->Hdr))
	{
		initParams.flags |= FFX_FSR2_ENABLE_HIGH_DYNAMIC_RANGE;
	}
	if (config->JitterCancellation.value_or(inParams->JitterMotion))
	{
		initParams.flags |= FFX_FSR2_ENABLE_MOTION_VECTORS_JITTER_CANCELLATION;
	}
	if (config->DisplayResolution.value_or(!inParams->LowRes))
	{
		initParams.flags |= FFX_FSR2_ENABLE_DISPLAY_RESOLUTION_MOTION_VECTORS;
	}
	
	errorCode = ffxFsr2ContextCreate(&deviceContext->FsrContext, &initParams);
	FFX_ASSERT(errorCode == FFX_OK);
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_ReleaseFeature(NVSDK_NGX_Handle* InHandle)
{
	auto deviceContext = CyberFsrContext::instance()->Contexts[InHandle->Id].get();
	FfxErrorCode errorCode = ffxFsr2ContextDestroy(&deviceContext->FsrContext);
	FFX_ASSERT(errorCode == FFX_OK);
	CyberFsrContext::instance()->DeleteContext(InHandle);
	return NVSDK_NGX_Result_Success;
}

inline FfxResource Cyber_ffxGTextureResourceVK(FfxFsr2Context* fsrContext, NVSDK_NGX_Resource_VK* texture, const wchar_t* name)
{
	return ffxGetTextureResourceVK(fsrContext, texture->Resource.ImageViewInfo.Image, texture->Resource.ImageViewInfo.ImageView, texture->Resource.ImageViewInfo.Width, texture->Resource.ImageViewInfo.Height, texture->Resource.ImageViewInfo.Format, name);
}

inline FfxResource Cyber_ffxGTextureResourceVK(FfxFsr2Context* fsrContext, NVSDK_NGX_Resource_VK* texture, const wchar_t* name, const FfxResourceStates state)
{
	return ffxGetTextureResourceVK(fsrContext, texture->Resource.ImageViewInfo.Image, texture->Resource.ImageViewInfo.ImageView, texture->Resource.ImageViewInfo.Width, texture->Resource.ImageViewInfo.Height, texture->Resource.ImageViewInfo.Format, name, state);
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_EvaluateFeature(VkCommandBuffer InCmdList, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
	auto instance = CyberFsrContext::instance();
	const auto& config = instance->MyConfig;
	auto deviceContext = CyberFsrContext::instance()->Contexts[InFeatureHandle->Id].get();
	const auto& inParams = *dynamic_cast<const NvParameter*>(InParameters);

	auto color = (NVSDK_NGX_Resource_VK*)inParams.Feature.pInColor;
	auto depth = (NVSDK_NGX_Resource_VK*)inParams.pInDepth;
	auto motionVectors = (NVSDK_NGX_Resource_VK*)inParams.pInMotionVectors;
	auto exposureTexture = (NVSDK_NGX_Resource_VK*)inParams.pInExposureTexture;
	auto inputBiasColorMask = (NVSDK_NGX_Resource_VK*)inParams.pInBiasCurrentColorMask;
	auto transparencyMask = (NVSDK_NGX_Resource_VK*)inParams.pInTransparencyMask;
	auto output = (NVSDK_NGX_Resource_VK*)inParams.Feature.pInOutput;

	auto* fsrContext = &deviceContext->FsrContext;
	FfxFsr2DispatchDescription dispatchParameters = {};
	dispatchParameters.commandList = ffxGetCommandListVK(InCmdList);
	if (color)
		dispatchParameters.color = Cyber_ffxGTextureResourceVK(fsrContext, color, (wchar_t*)L"FSR2_InputColor");
	if (depth)
		dispatchParameters.depth = Cyber_ffxGTextureResourceVK(fsrContext, depth, (wchar_t*)L"FSR2_InputDepth");
	if (motionVectors)
		dispatchParameters.motionVectors = Cyber_ffxGTextureResourceVK(fsrContext, motionVectors, (wchar_t*)L"FSR2_InputMotionVectors");
	if (exposureTexture)
		dispatchParameters.exposure = Cyber_ffxGTextureResourceVK(fsrContext, exposureTexture, (wchar_t*)L"FSR2_InputExposure");
	if (inputBiasColorMask)
		dispatchParameters.reactive = Cyber_ffxGTextureResourceVK(fsrContext, inputBiasColorMask, (wchar_t*)L"FSR2_InputReactiveMap");
	if (transparencyMask)
		dispatchParameters.transparencyAndComposition = Cyber_ffxGTextureResourceVK(fsrContext, transparencyMask, (wchar_t*)L"FSR2_TransparencyAndCompositionMap");
	if (output)
		dispatchParameters.output = Cyber_ffxGTextureResourceVK(fsrContext, output, (wchar_t*)L"FSR2_OutputUpscaledColor", FFX_RESOURCE_STATE_UNORDERED_ACCESS);

	dispatchParameters.jitterOffset.x = inParams.InJitterOffsetX;
	dispatchParameters.jitterOffset.y = inParams.InJitterOffsetY;
	dispatchParameters.motionVectorScale.x = (float)inParams.InMVScaleX;
	dispatchParameters.motionVectorScale.y = (float)inParams.InMVScaleY;

	dispatchParameters.reset = inParams.InReset;

	float sharpness = Util::ConvertSharpness(inParams.Feature.InSharpness, config->SharpnessRange);
	dispatchParameters.enableSharpening = config->EnableSharpening.value_or(inParams.EnableSharpening);
	dispatchParameters.sharpness = config->Sharpness.value_or(sharpness);

	dispatchParameters.frameTimeDelta = inParams.InFrameTimeDeltaInMsec;
	dispatchParameters.preExposure = 1.0f;
	dispatchParameters.renderSize.width = inParams.InRenderSubrectDimensions.Width;
	dispatchParameters.renderSize.height = inParams.InRenderSubrectDimensions.Height;

	dispatchParameters.cameraFar = deviceContext->ViewMatrix->GetFarPlane();
	dispatchParameters.cameraNear = deviceContext->ViewMatrix->GetNearPlane();
	dispatchParameters.cameraFovAngleVertical = DirectX::XMConvertToRadians(deviceContext->ViewMatrix->GetFov());
	FfxErrorCode errorCode = ffxFsr2ContextDispatch(fsrContext, &dispatchParameters);
	FFX_ASSERT(errorCode == FFX_OK);
#ifdef _DEBUG
	deviceContext->DebugLayer->Render(InCmdList);
#endif

	return NVSDK_NGX_Result_Success;
}