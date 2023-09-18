#include "pch.h"
#include "Config.h"
#include "CyberFsr.h"
#include "DirectXHooks.h"
#include "Util.h"

#ifdef CyberFSR_DO_VULKAN

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_VULKAN_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, VkInstance InInstance, VkPhysicalDevice InPD, VkDevice InDevice, PFN_vkGetInstanceProcAddr InGIPA, PFN_vkGetDeviceProcAddr InGDPA, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	CyberLogArgs(InApplicationId, InApplicationDataPath, InInstance, InPD, InDevice, InGIPA, InGDPA, InFeatureInfo, InSDKVersion);

	CyberFsrContext::instance()->VulkanDevice = InDevice;
	CyberFsrContext::instance()->VulkanInstance = InInstance;
	CyberFsrContext::instance()->VulkanPhysicalDevice = InPD;
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_VULKAN_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, VkInstance InInstance, VkPhysicalDevice InPD, VkDevice InDevice, PFN_vkGetInstanceProcAddr InGIPA, PFN_vkGetDeviceProcAddr InGDPA, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	CyberLogArgs(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InInstance, InPD, InDevice, InGIPA, InGDPA, InFeatureInfo, InSDKVersion);

	return NVSDK_NGX_VULKAN_Init(0x1337, InApplicationDataPath, InInstance, InPD, InDevice, InGIPA, InGDPA, InFeatureInfo, InSDKVersion);
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_VULKAN_Init_with_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, VkInstance InInstance, VkPhysicalDevice InPD, VkDevice InDevice, PFN_vkGetInstanceProcAddr InGIPA, PFN_vkGetDeviceProcAddr InGDPA, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	CyberLogArgs(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InInstance, InPD, InDevice, InGIPA, InGDPA, InFeatureInfo, InSDKVersion);

	return NVSDK_NGX_VULKAN_Init(0x1337, InApplicationDataPath, InInstance, InPD, InDevice, InGIPA, InGDPA, InFeatureInfo, InSDKVersion);
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_Shutdown(void)
{
	CyberLogArgs();

	CyberFsrContext::instance()->VulkanDevice = nullptr;
	CyberFsrContext::instance()->VulkanInstance = nullptr;
	CyberFsrContext::instance()->VulkanPhysicalDevice = nullptr;
	CyberFsrContext::instance()->NvParameterInstance->Params.clear();
	CyberFsrContext::instance()->Contexts.clear();
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_Shutdown1(VkDevice InDevice)
{
	CyberLogArgs(InDevice);

	CyberFsrContext::instance()->VulkanDevice = nullptr;
	CyberFsrContext::instance()->VulkanInstance = nullptr;
	CyberFsrContext::instance()->VulkanPhysicalDevice = nullptr;
	CyberFsrContext::instance()->NvParameterInstance->Params.clear();
	CyberFsrContext::instance()->Contexts.clear();
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_VULKAN_GetParameters(NVSDK_NGX_Parameter** OutParameters)
{
	CyberLogArgs(OutParameters);

	*OutParameters = CyberFsrContext::instance()->NvParameterInstance->AllocateParameters();
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_AllocateParameters(NVSDK_NGX_Parameter** OutParameters)
{
	CyberLogArgs(OutParameters);

	*OutParameters = Hyper_NGX_Parameter::instance()->AllocateParameters();
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters)
{
	CyberLogArgs(OutParameters);

	*OutParameters = Hyper_NGX_Parameter::instance()->AllocateParameters();
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_DestroyParameters(NVSDK_NGX_Parameter* InParameters)
{
	CyberLogArgs(InParameters);

	Hyper_NGX_Parameter::instance()->DeleteParameters((Hyper_NGX_Parameter*)InParameters);
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId, const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes)
{
	CyberLogArgs(InFeatureId, InParameters, OutSizeInBytes);

	auto instance = CyberFsrContext::instance();
	*OutSizeInBytes = ffxFsr2GetScratchMemorySizeVK(instance->VulkanPhysicalDevice);
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_CreateFeature(VkCommandBuffer InCmdBuffer, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
	CyberLogArgs(InCmdBuffer, InFeatureID, InParameters, OutHandle);

	return NVSDK_NGX_VULKAN_CreateFeature1(CyberFsrContext::instance()->VulkanDevice, InCmdBuffer, InFeatureID, InParameters, OutHandle);
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_CreateFeature1(VkDevice InDevice, VkCommandBuffer InCmdList, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
	CyberLogArgs(InDevice, InCmdList, InFeatureID, InParameters, OutHandle);

	const auto inParams = static_cast<const Hyper_NGX_Parameter*>(InParameters);

	auto instance = CyberFsrContext::instance();
	auto& config = instance->MyConfig;
	auto deviceContext = instance->CreateContext();
	deviceContext->ViewMatrix = ViewMatrixHook::Create(*config);
#ifdef _DEBUG
#ifdef CyberFSR_DO_OVERLAY1
	deviceContext->DebugLayer = std::make_unique<DebugOverlay>();
#endif
#endif

	* OutHandle = &deviceContext->Handle;

	auto initParams = deviceContext->FsrContextDescription;

	const size_t scratchBufferSize = ffxFsr2GetScratchMemorySizeVK(instance->VulkanPhysicalDevice);
	deviceContext->ScratchBuffer = std::vector<unsigned char>(scratchBufferSize);
	auto scratchBuffer = deviceContext->ScratchBuffer.data();

	FfxErrorCode errorCode = ffxFsr2GetInterfaceVK(&initParams.callbacks, scratchBuffer, scratchBufferSize, instance->VulkanPhysicalDevice, vkGetDeviceProcAddr);
	FFX_ASSERT(errorCode == FFX_OK);

	initParams.device = ffxGetDeviceVK(InDevice);
	initParams.maxRenderSize.width = inParams->renderSizeMax.Width;
	initParams.maxRenderSize.height = inParams->renderSizeMax.Height;
	initParams.displaySize.width = inParams->windowSize.Width;
	initParams.displaySize.height = inParams->windowSize.Height;

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
	CyberLogArgs(InHandle);

	auto deviceContext = CyberFsrContext::instance()->Contexts[InHandle->Id].get();
	FfxErrorCode errorCode = ffxFsr2ContextDestroy(&deviceContext->FsrContext);
	FFX_ASSERT(errorCode == FFX_OK);
	CyberFsrContext::instance()->DeleteContext(InHandle);
	return NVSDK_NGX_Result_Success;
}

#define  CyberFSR_VK_DUMP

#ifdef CyberFSR_VK_DUMP

std::wstring string_to_wstring(const std::string& str) {
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
	std::wstring wstr(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
	return wstr;
}

void DumpImageViewInfo(NVSDK_NGX_ImageViewInfo_VK* imageViewInfo, const std::string& resourceName) {
	std::wstring wResourceName = string_to_wstring(resourceName);
	std::wstring dump;

	if (imageViewInfo) {
		dump += wResourceName + L" Image View Info:\n";
		dump += L"  Width: " + std::to_wstring(imageViewInfo->Width) + L"\n";
		dump += L"  Height: " + std::to_wstring(imageViewInfo->Height) + L"\n";
		dump += L"  Format: " + std::to_wstring(imageViewInfo->Format) + L"\n";
		dump += L"  Subresource Range Aspect Mask: " + std::to_wstring(imageViewInfo->SubresourceRange.aspectMask) + L"\n";
		// ... any other details you might want
	}
	else {
		dump += wResourceName + L" is NULL\n";
	}

	CyberLOGvi(wResourceName, dump);
}

void DumpBufferInfo(NVSDK_NGX_BufferInfo_VK* bufferInfo, const std::string& resourceName) {
	std::wstring wResourceName = string_to_wstring(resourceName);
	std::wstring dump;

	if (bufferInfo) {
		dump += wResourceName + L" Buffer Info:\n";
		dump += L"  SizeInBytes: " + std::to_wstring(bufferInfo->SizeInBytes) + L"\n";
		// ... any other details you might want
	}
	else {
		dump += wResourceName + L" is NULL\n";
	}

	CyberLOGvi(wResourceName, dump);
}

#endif 


NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_VULKAN_EvaluateFeature(VkCommandBuffer InCmdList, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
	CyberLogArgs(InCmdList, InFeatureHandle, InParameters, InCallback);

	auto instance = CyberFsrContext::instance();
	auto& config = instance->MyConfig;
	auto deviceContext = CyberFsrContext::instance()->Contexts[InFeatureHandle->Id].get();
	const auto inParams = static_cast<const Hyper_NGX_Parameter*>(InParameters);

	auto color = (NVSDK_NGX_Resource_VK*)inParams->Color;
	auto depth = (NVSDK_NGX_Resource_VK*)inParams->Depth;
	auto motionVectors = (NVSDK_NGX_Resource_VK*)inParams->MotionVectors;
	auto exposureTexture = (NVSDK_NGX_Resource_VK*)inParams->ExposureTexture;
	auto inputBiasColorMask = (NVSDK_NGX_Resource_VK*)inParams->InputBiasCurrentColorMask;
	auto transparencyMask = (NVSDK_NGX_Resource_VK*)inParams->TransparencyMask;
	auto output = (NVSDK_NGX_Resource_VK*)inParams->Output;

	auto* fsrContext = &deviceContext->FsrContext;
	FfxFsr2DispatchDescription dispatchParameters = {};
	dispatchParameters.commandList = ffxGetCommandListVK(InCmdList);

#ifdef CyberFSR_VK_DUMP
	DumpImageViewInfo(&color->Resource.ImageViewInfo, "Color");
	DumpImageViewInfo(&depth->Resource.ImageViewInfo, "Depth");
	DumpImageViewInfo(&motionVectors->Resource.ImageViewInfo, "MotionVectors");
	DumpImageViewInfo(&exposureTexture->Resource.ImageViewInfo, "ExposureTexture");
	DumpImageViewInfo(&inputBiasColorMask->Resource.ImageViewInfo, "InputBiasColorMask");
	DumpImageViewInfo(&transparencyMask->Resource.ImageViewInfo, "TransparencyMask");
	DumpImageViewInfo(&output->Resource.ImageViewInfo, "Output");

#endif


	if (color)
		dispatchParameters.color = ffxGetTextureResourceVK(fsrContext, color->Resource.ImageViewInfo.Image, color->Resource.ImageViewInfo.ImageView, color->Resource.ImageViewInfo.Width, color->Resource.ImageViewInfo.Height, color->Resource.ImageViewInfo.Format, (wchar_t*)L"FSR2_InputColor");

	if (depth)
		dispatchParameters.depth = ffxGetTextureResourceVK(fsrContext, depth->Resource.ImageViewInfo.Image, depth->Resource.ImageViewInfo.ImageView, depth->Resource.ImageViewInfo.Width, depth->Resource.ImageViewInfo.Height, depth->Resource.ImageViewInfo.Format, (wchar_t*)L"FSR2_InputDepth");

	if (motionVectors)
		dispatchParameters.motionVectors = ffxGetTextureResourceVK(fsrContext, motionVectors->Resource.ImageViewInfo.Image, motionVectors->Resource.ImageViewInfo.ImageView, motionVectors->Resource.ImageViewInfo.Width, motionVectors->Resource.ImageViewInfo.Height, motionVectors->Resource.ImageViewInfo.Format, (wchar_t*)L"FSR2_InputMotionVectors");

	if (exposureTexture)
		dispatchParameters.exposure = ffxGetTextureResourceVK(fsrContext, exposureTexture->Resource.ImageViewInfo.Image, exposureTexture->Resource.ImageViewInfo.ImageView, exposureTexture->Resource.ImageViewInfo.Width, exposureTexture->Resource.ImageViewInfo.Height, exposureTexture->Resource.ImageViewInfo.Format, (wchar_t*)L"FSR2_InputExposure");

	if (inputBiasColorMask)
		dispatchParameters.reactive = ffxGetTextureResourceVK(fsrContext, inputBiasColorMask->Resource.ImageViewInfo.Image, inputBiasColorMask->Resource.ImageViewInfo.ImageView, inputBiasColorMask->Resource.ImageViewInfo.Width, inputBiasColorMask->Resource.ImageViewInfo.Height, inputBiasColorMask->Resource.ImageViewInfo.Format, (wchar_t*)L"FSR2_InputReactiveMap");

	if (transparencyMask)
		dispatchParameters.transparencyAndComposition = ffxGetTextureResourceVK(fsrContext, transparencyMask->Resource.ImageViewInfo.Image, transparencyMask->Resource.ImageViewInfo.ImageView, transparencyMask->Resource.ImageViewInfo.Width, transparencyMask->Resource.ImageViewInfo.Height, transparencyMask->Resource.ImageViewInfo.Format, (wchar_t*)L"FSR2_TransparencyAndCompositionMap");

	if (output)
		dispatchParameters.output = ffxGetTextureResourceVK(fsrContext, output->Resource.ImageViewInfo.Image, output->Resource.ImageViewInfo.ImageView, output->Resource.ImageViewInfo.Width, output->Resource.ImageViewInfo.Height, output->Resource.ImageViewInfo.Format, (wchar_t*)L"FSR2_OutputUpscaledColor", FFX_RESOURCE_STATE_UNORDERED_ACCESS);

	dispatchParameters.jitterOffset.x = inParams->JitterOffsetX;
	dispatchParameters.jitterOffset.y = inParams->JitterOffsetY;
	dispatchParameters.motionVectorScale.x = (float)inParams->MVScaleX;
	dispatchParameters.motionVectorScale.y = (float)inParams->MVScaleY;

	dispatchParameters.reset = inParams->ResetRender;

	float sharpness = Util::ConvertSharpness(inParams->Sharpness, config->SharpnessRange);
	dispatchParameters.enableSharpening = config->EnableSharpening.value_or(inParams->EnableSharpening);
	dispatchParameters.sharpness = config->Sharpness.value_or(sharpness);

	static double lastFrameTime = 0.0;
	double currentTime = Util::MillisecondsNow();
	double deltaTime = (currentTime - lastFrameTime);
	lastFrameTime = currentTime;

	dispatchParameters.frameTimeDelta = (float)deltaTime;
	dispatchParameters.preExposure = 1.0f;
	dispatchParameters.renderSize.width = inParams->renderSize.Width;
	dispatchParameters.renderSize.height = inParams->renderSize.Height;

	dispatchParameters.cameraFar = deviceContext->ViewMatrix->GetFarPlane();
	dispatchParameters.cameraNear = deviceContext->ViewMatrix->GetNearPlane();
	dispatchParameters.cameraFovAngleVertical = DirectX::XMConvertToRadians(deviceContext->ViewMatrix->GetFov());
	FfxErrorCode errorCode = ffxFsr2ContextDispatch(fsrContext, &dispatchParameters);
	FFX_ASSERT(errorCode == FFX_OK);

#ifdef _DEBUG
#ifdef CyberFSR_DO_OVERLAY1
	deviceContext->DebugLayer->Render();
#endif
#endif

	return NVSDK_NGX_Result_Success;
}

#endif //  CyberFSR_DO_VULKAN