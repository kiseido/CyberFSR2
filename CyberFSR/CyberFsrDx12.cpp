#include "pch.h"
#include "Config.h"
#include "CyberFsr.h"
#include "DirectXHooks.h"
#include "Util.h"

#include "CyberMacros.cpp"

// external\FidelityFX-FSR2\src\ffx-fsr2-api\ffx_fsr2_interface.h
// external\nvngx_dlss_sdk\include\nvsdk_ngx_defs.h
// external\nvngx_dlss_sdk\include\nvsdk_ngx_helpers.h

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D12_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D12Device* InDevice, NVSDK_NGX_Version InSDKVersion, const char* Apointer1, const char* Apointer2)
{
	// cyberpunk enters here
	// cyberpunk id == 0x0000000005f83393

	auto output = NVSDK_NGX_Result_Success;

	//CyberFSR::FeatureCommonInfo.LoggingInfo.LoggingCallback("Hello!", NVSDK_NGX_LOGGING_LEVEL_OFF, NVSDK_NGX_Feature_SuperSampling);

	return output;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	// InFeatureInfo has important info!!!?!
	auto output = NVSDK_NGX_Result_Success;

	// if this is cyberpunk, InFeatureInfo's value seems to actually be InSDKVersion


	output = NVSDK_NGX_D3D12_Init_Ext(InApplicationId, InApplicationDataPath, InDevice, InSDKVersion, (char*)InFeatureInfo, 0);
	//output = NVSDK_NGX_D3D12_Init_Ext(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, 0);

	return output;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D12_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	// InFeatureInfo has important info!!!?!

	auto output = NVSDK_NGX_Result_Success;

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
		CyberFSR::BadThingHappened();
		output = NVSDK_NGX_Result_Fail;
		break;
	default:
		// we should not see this state
		CyberFSR::BadThingHappened();
		output = NVSDK_NGX_Result_Fail;
		break;
	}
	return output;
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


// Nevertheless, due to the possibility that the user will be using an older driver
// version, NVSDK_NGX_GetParameters may still be used as a fallback if
// NVSDK_NGX_AllocateParameters
// or NVSDK_NGX_GetCapabilityParameters return NVSDK_NGX_Result_FAIL_OutOfDate.

// Parameter maps output by NVSDK_NGX_GetParameters are also pre-populated
// with NGX capabilities and available features.
// 
//Deprecated Parameter Function - Internal Memory Tracking
NVSDK_NGX_Result NVSDK_NGX_D3D12_GetParameters(NVSDK_NGX_Parameter** OutParameters)
{
	//*OutParameters = CyberContext::instance()->AllocateParameter();
	*OutParameters = CyberNvParameter::GetFreshCapabilityParameter();
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
	NVSDK_NGX_Result output = NVSDK_NGX_Result_Fail;

	switch (InFeatureID)
	{
	case NVSDK_NGX_Feature_Reserved0:
		CyberFSR::BadThingHappened();
		break;
	case NVSDK_NGX_Feature_SuperSampling:
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

		initParams.maxRenderSize.width = inParams->Max_Render_Width;
		initParams.maxRenderSize.height = inParams->Max_Render_Height;
		initParams.displaySize.width = inParams->OutWidth;
		initParams.displaySize.height = inParams->OutHeight;

		initParams.flags = 0 |
			(config->HDR.value_or(inParams->Hdr) ? FFX_FSR2_ENABLE_HIGH_DYNAMIC_RANGE : 0) |
			(config->DisplayResolution.value_or(!inParams->LowRes) ? FFX_FSR2_ENABLE_DISPLAY_RESOLUTION_MOTION_VECTORS : 0) |
			(config->JitterCancellation.value_or(inParams->JitterMotion) ? FFX_FSR2_ENABLE_MOTION_VECTORS_JITTER_CANCELLATION : 0) |
			(config->DepthInverted.value_or(inParams->DepthInverted) ? FFX_FSR2_ENABLE_DEPTH_INVERTED : 0) |
			(config->InfiniteFarPlane.value_or(false) ? FFX_FSR2_ENABLE_DEPTH_INFINITE : 0) |
			(config->AutoExposure.value_or(inParams->AutoExposure) ? FFX_FSR2_ENABLE_AUTO_EXPOSURE : 0) |
			(inParams->EnableDynamicResolution ? FFX_FSR2_ENABLE_DYNAMIC_RESOLUTION : 0) |
			(inParams->EnableTexture1DUsage ? FFX_FSR2_ENABLE_TEXTURE1D_USAGE : 0);

		errorCode = ffxFsr2ContextCreate(&deviceContext->FsrContext, &initParams);
		FFX_ASSERT(errorCode == FFX_OK);

		HookSetComputeRootSignature(InCmdList);

		output = NVSDK_NGX_Result_Success;
	}
		break;
	case NVSDK_NGX_Feature_InPainting:
		CyberFSR::BadThingHappened();
		break;
	case NVSDK_NGX_Feature_ImageSuperResolution:
		CyberFSR::BadThingHappened();
		break;
	case NVSDK_NGX_Feature_SlowMotion:
		CyberFSR::BadThingHappened();
		break;
	case NVSDK_NGX_Feature_VideoSuperResolution:
		CyberFSR::BadThingHappened();
		break;
	case NVSDK_NGX_Feature_Reserved1:
		CyberFSR::BadThingHappened();
		break;
	case NVSDK_NGX_Feature_Reserved2:
		CyberFSR::BadThingHappened();
		break;
	case NVSDK_NGX_Feature_Reserved3:
		CyberFSR::BadThingHappened();
		break;
	case NVSDK_NGX_Feature_ImageSignalProcessing:
		CyberFSR::BadThingHappened();
		break;
	case NVSDK_NGX_Feature_DeepResolve:
		CyberFSR::BadThingHappened();
		break;
	case NVSDK_NGX_Feature_Reserved4:
		CyberFSR::BadThingHappened();
		break;
	case NVSDK_NGX_Feature_Count:
		CyberFSR::BadThingHappened();
		break;
	case NVSDK_NGX_Feature_Reserved_SDK:
		CyberFSR::BadThingHappened();
		break;
	case NVSDK_NGX_Feature_Reserved_Core:
		CyberFSR::BadThingHappened();
		break;
	case NVSDK_NGX_Feature_Reserved_Unknown:
		CyberFSR::BadThingHappened();
		break;
	default:
		CyberFSR::BadThingHappened();
		break;
	}
	return output;
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

	bool shouldCancel = false;

	if (InCallback != nullptr)
		InCallback(0, shouldCancel);

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

	if (InCallback != nullptr)
		InCallback(1, shouldCancel);

	ID3D12Device* device;
	InCmdList->GetDevice(IID_PPV_ARGS(&device));
	auto instance = CyberContext::instance();
	auto config = instance->MyConfig;
	auto deviceContext = CyberContext::instance()->Contexts[InFeatureHandle->Id].get();

	if (InCallback != nullptr)
		InCallback(5, shouldCancel);

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

		if (InCallback != nullptr)
			InCallback(10, shouldCancel);

		//Not sure if these two actually work
		if (!config->DisableReactiveMask.value_or(false))
		{
			//dispatchParameters.reactive = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->InputBiasCurrentColorMask, L"FSR2_InputReactiveMap");
			dispatchParameters.reactive = {NULL};
			//dispatchParameters.transparencyAndComposition = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->TransparencyMask, L"FSR2_TransparencyAndCompositionMap");
			dispatchParameters.transparencyAndComposition = {NULL};
		}

		dispatchParameters.output = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->Output, L"FSR2_OutputUpscaledColor", FFX_RESOURCE_STATE_UNORDERED_ACCESS);

		dispatchParameters.jitterOffset.x = inParams->JitterOffsetX;
		dispatchParameters.jitterOffset.y = inParams->JitterOffsetY;

		dispatchParameters.motionVectorScale.x = (float)inParams->MVScaleX;
		dispatchParameters.motionVectorScale.y = (float)inParams->MVScaleY;

		dispatchParameters.reset = inParams->ResetRender;

		dispatchParameters.enableSharpening = config->EnableSharpening.value_or(inParams->EnableSharpening);
		
		if (dispatchParameters.enableSharpening) {

			if (config->Sharpness.has_value())
			{
				dispatchParameters.sharpness = config->Sharpness.value();
			}
			else
			{
				float sharpness = CyberUtil::ConvertSharpness(inParams->Sharpness, config->SharpnessRange);
				if (sharpness > 0 && sharpness <= 1.0f) 
				{
					dispatchParameters.sharpness = sharpness;
				}
			}
		}
		if (InCallback != nullptr)
			InCallback(20, shouldCancel);

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

		if (InCallback != nullptr)
			InCallback(30, shouldCancel);

		//Hax Zone
		dispatchParameters.cameraFar = deviceContext->ViewMatrix->GetFarPlane();
		dispatchParameters.cameraNear = deviceContext->ViewMatrix->GetNearPlane();
			dispatchParameters.cameraFovAngleVertical = DirectX::XMConvertToRadians(deviceContext->ViewMatrix->GetFov());
		FfxErrorCode errorCode = ffxFsr2ContextDispatch(fsrContext, &dispatchParameters);
		FFX_ASSERT(errorCode == FFX_OK);

		if (InCallback != nullptr)
			InCallback(40, shouldCancel);

		InCmdList->SetComputeRootSignature(orgRootSig);
	}
#ifdef DEBUG_FEATURES
	deviceContext->DebugLayer->AddText(L"DLSS2FSR", DirectX::XMFLOAT2(1.0, 1.0));
	deviceContext->DebugLayer->Render(InCmdList);
#endif

	myCommandList = InCmdList;

	if (InCallback != nullptr)
		InCallback(100, shouldCancel);

	return NVSDK_NGX_Result_Success;
}
