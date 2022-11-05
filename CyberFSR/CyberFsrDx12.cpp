#include "pch.h"
#include "Config.h"
#include "CyberFsr.h"
#include "DirectXHooks.h"
#include "Util.h"

#include "CyberMacros.cpp"

// external\FidelityFX-FSR2\src\ffx-fsr2-api\ffx_fsr2_interface.h
// external\nvngx_dlss_sdk\include\nvsdk_ngx_defs.h
// external\nvngx_dlss_sdk\include\nvsdk_ngx_helpers.h

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D12_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath,
	ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion,
	unsigned long long unknown0)
{
	// cyberpunk enters here
	// cyberpunk 2077 id: 100152211, sdk version: 100152211
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	return NVSDK_NGX_D3D12_Init_Ext(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, 0);
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D12_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	CyberFSR::IncomingEngineType = InEngineType;

	switch (InEngineType)
	{
	case NVSDK_NGX_ENGINE_TYPE_CUSTOM:
		break;
	case NVSDK_NGX_ENGINE_TYPE_UNREAL: 
		break;
	case NVSDK_NGX_ENGINE_TYPE_UNITY:
		break;
	case NVSDK_NGX_ENGINE_TYPE_OMNIVERSE:
		break;
	case NVSDK_NGX_ENGINE_COUNT:
		// we should not see this state
		return NVSDK_NGX_Result_Fail;
	default:
		// we should not see this state
		return NVSDK_NGX_Result_Fail;
		break;
	}
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D12_Shutdown(void)
{
	CyberContext::instance()->Parameters.clear();
	CyberContext::instance()->Contexts.clear();
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D12_Shutdown1(ID3D12Device* InDevice)
{
	CyberContext::instance()->Parameters.clear();
	CyberContext::instance()->Contexts.clear();
	return NVSDK_NGX_Result_Success;
}

//Deprecated Parameter Function - Internal Memory Tracking
NVSDK_NGX_Result NVSDK_NGX_D3D12_GetParameters(NVSDK_NGX_Parameter** OutParameters)
{
	//*OutParameters = CyberContext::instance()->AllocateParameter();
	*OutParameters = CyberNvParameter::GetFreshParameter();
	return NVSDK_NGX_Result_Success;
}

//TODO External Memory Tracking
NVSDK_NGX_Result NVSDK_NGX_D3D12_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters)
{
	*OutParameters = CyberNvParameter::GetFreshCapabilityParameter();
	return NVSDK_NGX_Result_Success;
}

//TODO
NVSDK_NGX_Result NVSDK_NGX_D3D12_AllocateParameters(NVSDK_NGX_Parameter** OutParameters)
{
	*OutParameters = CyberNvParameter::GetFreshParameter();
	return NVSDK_NGX_Result_Success;
}

//TODO
NVSDK_NGX_Result NVSDK_NGX_D3D12_DestroyParameters(NVSDK_NGX_Parameter* InParameters)
{
	CyberNvParameter::RecycleParameter((CyberNvParameter*)InParameters);
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId,
	const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes)
{
	*OutSizeInBytes = ffxFsr2GetScratchMemorySizeDX12();
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_CreateFeature(ID3D12GraphicsCommandList* InCmdList, NVSDK_NGX_Feature InFeatureID,
	const NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
	const auto inParams = dynamic_cast<const CyberNvParameter*>(InParameters);

	ID3D12Device* device;
	InCmdList->GetDevice(IID_PPV_ARGS(&device));

	auto instance = CyberContext::instance();
	auto config = instance->MyConfig;
	auto deviceContext = CyberContext::instance()->CreateContext();
	deviceContext->ViewMatrix = CyberHooker::Create(*config);
#ifdef DEBUG_FEATURES
	deviceContext->DebugLayer = std::make_unique<DebugOverlay>(device, InCmdList);
#endif

	* OutHandle = &deviceContext->Handle;

	auto initParams = deviceContext->FsrContextDescription;

	const size_t scratchBufferSize = ffxFsr2GetScratchMemorySizeDX12();
	deviceContext->ScratchBuffer = std::vector<unsigned char>(scratchBufferSize);
	auto scratchBuffer = deviceContext->ScratchBuffer.data();

	FfxErrorCode errorCode = ffxFsr2GetInterfaceDX12(&initParams.callbacks, device, scratchBuffer, scratchBufferSize);
	FFX_ASSERT(errorCode == FFX_OK);

	initParams.device = ffxGetDeviceDX12(device);
	initParams.maxRenderSize.width = inParams->Width;
	initParams.maxRenderSize.height = inParams->Height;
	initParams.displaySize.width = inParams->OutWidth;
	initParams.displaySize.height = inParams->OutHeight;

	initParams.flags = 0 |
		(config->HDR				.value_or(inParams->Hdr)		? FFX_FSR2_ENABLE_HIGH_DYNAMIC_RANGE : 0) |
		(config->DisplayResolution	.value_or(!inParams->LowRes)		? FFX_FSR2_ENABLE_DISPLAY_RESOLUTION_MOTION_VECTORS : 0) |
		(config->JitterCancellation	.value_or(inParams->JitterMotion)	? FFX_FSR2_ENABLE_MOTION_VECTORS_JITTER_CANCELLATION : 0) |
		(config->DepthInverted		.value_or(inParams->DepthInverted)	? FFX_FSR2_ENABLE_DEPTH_INVERTED : 0) |
		(config->InfiniteFarPlane	.value_or(false)					? FFX_FSR2_ENABLE_DEPTH_INFINITE : 0) |
		(config->AutoExposure		.value_or(inParams->AutoExposure)	? FFX_FSR2_ENABLE_AUTO_EXPOSURE : 0) |
		(inParams->EnableDynamicResolution ? FFX_FSR2_ENABLE_DYNAMIC_RESOLUTION : 0) |
		(inParams->EnableTexture1DUsage ? FFX_FSR2_ENABLE_TEXTURE1D_USAGE : 0);

	errorCode = ffxFsr2ContextCreate(&deviceContext->FsrContext, &initParams);
	FFX_ASSERT(errorCode == FFX_OK);

	HookSetComputeRootSignature(InCmdList);

	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_ReleaseFeature(NVSDK_NGX_Handle* InHandle)
{
	auto deviceContext = CyberContext::instance()->Contexts[InHandle->Id].get();
	FfxErrorCode errorCode = ffxFsr2ContextDestroy(&deviceContext->FsrContext);
	FFX_ASSERT(errorCode == FFX_OK);
	CyberContext::instance()->DeleteContext(InHandle); // delete all associated parameters too?
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_EvaluateFeature(ID3D12GraphicsCommandList* InCmdList, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
	ID3D12RootSignature* orgRootSig = nullptr;

	rootSigMutex.lock();
	if (commandListVector.contains(InCmdList))
	{
		orgRootSig = commandListVector[InCmdList];
	}
	else
	{
		printf("Cant find the RootSig\n");
	}
	rootSigMutex.unlock();

	ID3D12Device* device;
	InCmdList->GetDevice(IID_PPV_ARGS(&device));
	auto instance = CyberContext::instance();
	auto config = instance->MyConfig;
	auto deviceContext = CyberContext::instance()->Contexts[InFeatureHandle->Id].get();

	if (orgRootSig)
	{
		const auto inParams = dynamic_cast<const CyberNvParameter*>(InParameters);

		auto* fsrContext = &deviceContext->FsrContext;

		FfxFsr2DispatchDescription dispatchParameters = {};
		dispatchParameters.commandList = ffxGetCommandListDX12(InCmdList);
		dispatchParameters.color = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->Color, L"FSR2_InputColor");
		dispatchParameters.depth = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->Depth, L"FSR2_InputDepth");
		dispatchParameters.motionVectors = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->MotionVectors, L"FSR2_InputMotionVectors");
		dispatchParameters.exposure = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->ExposureTexture, L"FSR2_InputExposure");

		//Not sure if these two actually work
		if (!config->DisableReactiveMask.value_or(false))
		{
			dispatchParameters.reactive = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->InputBiasCurrentColorMask, L"FSR2_InputReactiveMap");
			dispatchParameters.transparencyAndComposition = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->TransparencyMask, L"FSR2_TransparencyAndCompositionMap");
		}

		dispatchParameters.output = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->Output, L"FSR2_OutputUpscaledColor", FFX_RESOURCE_STATE_UNORDERED_ACCESS);

		dispatchParameters.jitterOffset.x = inParams->JitterOffsetX;
		dispatchParameters.jitterOffset.y = inParams->JitterOffsetY;

		dispatchParameters.motionVectorScale.x = (float)inParams->MVScaleX;
		dispatchParameters.motionVectorScale.y = (float)inParams->MVScaleY;

		dispatchParameters.reset = inParams->ResetRender;

		float sharpness = CyberUtil::ConvertSharpness(inParams->Sharpness, config->SharpnessRange);
		
		if (config->EnableSharpening.value_or(inParams->EnableSharpening)) {
			dispatchParameters.enableSharpening = true;
			if (config->Sharpness.has_value())
			{
				dispatchParameters.sharpness = config->Sharpness.value();
			}
			else if (sharpness > 0 && sharpness <= 1.0f) {
				dispatchParameters.sharpness = sharpness;
			}
		}

		//deltatime hax
		static double lastFrameTime;
		double currentTime = CyberUtil::MillisecondsNow();
		double deltaTime = (currentTime - lastFrameTime);
		lastFrameTime = currentTime;

		dispatchParameters.frameTimeDelta = deltaTime;
		//dispatchParameters.frameTimeDelta = inParams->FrameTimeDeltaInMsec;
		dispatchParameters.preExposure = inParams->preExposure;
		dispatchParameters.renderSize.width = inParams->Width;
		dispatchParameters.renderSize.height = inParams->Height;

		//Hax Zone
		dispatchParameters.cameraFar = deviceContext->ViewMatrix->GetFarPlane();
		dispatchParameters.cameraNear = deviceContext->ViewMatrix->GetNearPlane();
		dispatchParameters.cameraFovAngleVertical = DirectX::XMConvertToRadians(deviceContext->ViewMatrix->GetFov());
		FfxErrorCode errorCode = ffxFsr2ContextDispatch(fsrContext, &dispatchParameters);
		FFX_ASSERT(errorCode == FFX_OK);

		InCmdList->SetComputeRootSignature(orgRootSig);
	}
#ifdef DEBUG_FEATURES
	deviceContext->DebugLayer->AddText(L"DLSS2FSR", DirectX::XMFLOAT2(1.0, 1.0));
	deviceContext->DebugLayer->Render(InCmdList);
#endif

	myCommandList = InCmdList;

	return NVSDK_NGX_Result_Success;
}
