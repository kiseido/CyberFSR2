#include "pch.h"
#include "Config.h"
#include "CyberFsr.h"
#include "DirectXHooks.h"
#include "Util.h"

#include "CyberMacros.cpp"

// dx 12 - > dx11 interop https://learn.microsoft.com/en-us/windows/win32/direct3d12/direct3d-12-with-direct3d-11--direct-2d-and-gdi

// external\FidelityFX-FSR2\src\ffx-fsr2-api\ffx_fsr2_interface.h
// external\nvngx_dlss_sdk\include\nvsdk_ngx_defs.h
// external\nvngx_dlss_sdk\include\nvsdk_ngx_helpers.h

extern CyberFSR::ViewMatrixArray const* internal;

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D11_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, NVSDK_NGX_Version InSDKVersion, const NVSDK_NGX_FeatureCommonInfo* APointer, const CyberFSR::ViewMatrixHook::Configured* unknown)
{
	// cyberpunk enters here
	// cyberpunk id == 0x5f83393 // version 0x13
	// horizon zero dawn id == 0x607fb07 // version 0x14

	internal = ((CyberFSR::ViewMatrixArray*)APointer->InternalData);

	switch (InApplicationId)
	{
	case 0x5f83393:
		//cyberpunk

		break;
	case 0x607fb07:
		//horizon zero dawn

		break;
	default:
		break;
	}

	auto output = NVSDK_NGX_Result_Success;

	//CyberFSR::FeatureCommonInfo.LoggingInfo.LoggingCallback("Hello!", NVSDK_NGX_LOGGING_LEVEL_OFF, NVSDK_NGX_Feature_SuperSampling);

	return output;
}

//NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D11_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, NVSDK_NGX_Version InSDKVersion, const char* Apointer1, const char* Apointer2)
//{
//	// cyberpunk enters here
//	// cyberpunk id == 0x0000000005f83393
//
//	auto output = NVSDK_NGX_Result_Success;
//
//	//CyberFSR::FeatureCommonInfo.LoggingInfo.LoggingCallback("Hello!", NVSDK_NGX_LOGGING_LEVEL_OFF, NVSDK_NGX_Feature_SuperSampling);
//
//	return output;
//}

NVSDK_NGX_Result NVSDK_NGX_D3D11_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	// InFeatureInfo has important info!!!?!
	auto output = NVSDK_NGX_Result_Success;

	// if this is cyberpunk, InFeatureInfo's value seems to actually be InSDKVersion


	output = NVSDK_NGX_D3D11_Init_Ext(InApplicationId, InApplicationDataPath, InDevice, InSDKVersion, InFeatureInfo, 0);
	//output = NVSDK_NGX_D3D11_Init_Ext(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, 0);

	return output;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D11_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
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

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Shutdown(void)
{
	CyberContext::instance()->Parameters.clear();
	CyberContext::instance()->Contexts.clear();
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Shutdown1(ID3D11Device* InDevice)
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
NVSDK_NGX_Result NVSDK_NGX_D3D11_GetParameters(NVSDK_NGX_Parameter** OutParameters)
{
	//*OutParameters = CyberContext::instance()->AllocateParameter();
	*OutParameters = CyberNvParameter::GetFreshCapabilityParameter();
	return NVSDK_NGX_Result_Success;
}

//TODO External Memory Tracking
NVSDK_NGX_Result NVSDK_NGX_D3D11_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters)
{
	*OutParameters = CyberNvParameter::GetFreshCapabilityParameter();
	return NVSDK_NGX_Result_Success;
}

//TODO
NVSDK_NGX_Result NVSDK_NGX_D3D11_AllocateParameters(NVSDK_NGX_Parameter** OutParameters)
{
	*OutParameters = CyberNvParameter::GetFreshParameter();
	return NVSDK_NGX_Result_Success;
}

//TODO
NVSDK_NGX_Result NVSDK_NGX_D3D11_DestroyParameters(NVSDK_NGX_Parameter* InParameters)
{
	CyberNvParameter::RecycleParameter((CyberNvParameter*)InParameters);
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId,
	const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes)
{
	*OutSizeInBytes = ffxFsr2GetScratchMemorySizeDX12();
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_CreateFeature(ID3D11DeviceContext* InDevCtx, NVSDK_NGX_Feature InFeatureID, const NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
	NVSDK_NGX_Result output = NVSDK_NGX_Result_Fail;

//	switch (InFeatureID)
//	{
//	case NVSDK_NGX_Feature_Reserved0:
//		CyberFSR::BadThingHappened();
//		break;
//	case NVSDK_NGX_Feature_SuperSampling:
//	{
//		const auto inParams = dynamic_cast<const CyberNvParameter*>(InParameters);
//
//		ID3D11Device* device = InDevCtx->;
//
//		auto instance = CyberContext::instance();
//		auto config = instance->MyConfig;
//		auto deviceContext = CyberContext::instance()->CreateContext();
//		deviceContext->ViewMatrix = CyberHooker::Create(*config);
//#ifdef DEBUG_FEATURES
//		deviceContext->DebugLayer = std::make_unique<DebugOverlay>(device, InCmdList);
//#endif
//
//		* OutHandle = &deviceContext->Handle;
//
//		auto initParams = deviceContext->FsrContextDescription;
//
//		const size_t scratchBufferSize = ffxFsr2GetScratchMemorySizeDX12();
//		deviceContext->ScratchBuffer = std::vector<unsigned char>(scratchBufferSize);
//		auto scratchBuffer = deviceContext->ScratchBuffer.data();
//
//		FfxErrorCode errorCode = ffxFsr2GetInterfaceDX12(&initParams.callbacks, device, scratchBuffer, scratchBufferSize);
//		CyberFSR::Util::FFXErrorCheck(errorCode);
//
//		initParams.device = ffxGetDeviceDX12(device);
//
//		initParams.maxRenderSize.width = CyberFSR::CyberFsrContext::FinalDisplayResolution.first;
//		initParams.maxRenderSize.height = CyberFSR::CyberFsrContext::FinalDisplayResolution.second;
//		initParams.displaySize.width = CyberFSR::CyberFsrContext::FinalDisplayResolution.first;
//		initParams.displaySize.height = CyberFSR::CyberFsrContext::FinalDisplayResolution.second;
//
//		initParams.flags = 0 |
//			(config->HDR.value_or(inParams->Hdr) ? FFX_FSR2_ENABLE_HIGH_DYNAMIC_RANGE : 0) |
//			(config->DisplayResolution.value_or(!inParams->LowRes) ? FFX_FSR2_ENABLE_DISPLAY_RESOLUTION_MOTION_VECTORS : 0) |
//			(config->JitterCancellation.value_or(inParams->JitterMotion) ? FFX_FSR2_ENABLE_MOTION_VECTORS_JITTER_CANCELLATION : 0) |
//			(config->DepthInverted.value_or(inParams->DepthInverted) ? FFX_FSR2_ENABLE_DEPTH_INVERTED : 0) |
//			(config->InfiniteFarPlane.value_or(false) ? FFX_FSR2_ENABLE_DEPTH_INFINITE : 0) |
//			(config->AutoExposure.value_or(inParams->AutoExposure) ? FFX_FSR2_ENABLE_AUTO_EXPOSURE : 0) |
//			(inParams->EnableDynamicResolution ? FFX_FSR2_ENABLE_DYNAMIC_RESOLUTION : 0) |
//			(inParams->EnableTexture1DUsage ? FFX_FSR2_ENABLE_TEXTURE1D_USAGE : 0);
//
//		errorCode = ffxFsr2ContextCreate(&deviceContext->FsrContext, &initParams);
//		CyberFSR::Util::FFXErrorCheck(errorCode);
//
//		HookSetComputeRootSignature(((ID3D12GraphicsCommandList*)InCmdList));
//
//		output = NVSDK_NGX_Result_Success;
//	}
//	break;
//	//case NVSDK_NGX_Feature_InPainting:
//	//case NVSDK_NGX_Feature_ImageSuperResolution:
//	//case NVSDK_NGX_Feature_SlowMotion:
//	//case NVSDK_NGX_Feature_VideoSuperResolution:
//	//case NVSDK_NGX_Feature_Reserved1:
//	//case NVSDK_NGX_Feature_Reserved2:
//	//case NVSDK_NGX_Feature_Reserved3:
//	//case NVSDK_NGX_Feature_ImageSignalProcessing:
//	//case NVSDK_NGX_Feature_DeepResolve:
//	//case NVSDK_NGX_Feature_Reserved4:
//	//case NVSDK_NGX_Feature_Count:
//	//case NVSDK_NGX_Feature_Reserved_SDK:
//	//case NVSDK_NGX_Feature_Reserved_Core:
//	//case NVSDK_NGX_Feature_Reserved_Unknown:
//	default:
//		CyberFSR::BadThingHappened();
//		break;
//	}
	return output;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_ReleaseFeature(NVSDK_NGX_Handle* InHandle)
{
	auto deviceContext = CyberContext::instance()->Contexts[InHandle->Id].get();
	FfxErrorCode errorCode = ffxFsr2ContextDestroy(&deviceContext->FsrContext);
	FFX_ASSERT(errorCode == FFX_OK);
	CyberContext::instance()->DeleteContext(InHandle); // delete all associated parameters too?
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_EvaluateFeature(ID3D11DeviceContext* InDevCtx, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
//	if (((CyberNvParameter*)InParameters)->SuperSampling_Available)
//	{
//		ID3D12RootSignature* orgRootSig = nullptr;
//
//		bool shouldCancel = false;
//
//		if (InCallback != nullptr)
//			InCallback(0, shouldCancel);
//
//		rootSigMutex.lock();
//		if (commandListVector.contains(((ID3D12GraphicsCommandList*)InCmdList)))
//		{
//			orgRootSig = commandListVector[((ID3D12GraphicsCommandList*)InCmdList)].first;
//		}
//		else
//		{
//			printf("Cant find the RootSig\n");
//		}
//		rootSigMutex.unlock();
//
//		if (InCallback != nullptr)
//			InCallback(1, shouldCancel);
//
//		ID3D12Device* device;
//		((ID3D12GraphicsCommandList*)InCmdList)->GetDevice(IID_PPV_ARGS(&device));
//		auto instance = CyberContext::instance();
//		auto config = instance->MyConfig;
//		auto deviceContext = CyberContext::instance()->Contexts[InFeatureHandle->Id].get();
//
//		if (InCallback != nullptr)
//			InCallback(5, shouldCancel);
//
//		if (orgRootSig)
//		{
//			const auto inParams = dynamic_cast<const CyberNvParameter*>(InParameters);
//
//			auto color = (ID3D12Resource*)inParams->Color;
//			auto depth = (ID3D12Resource*)inParams->Depth;
//			auto motionVectors = (ID3D12Resource*)inParams->MotionVectors;
//			auto exposureTexture = (ID3D12Resource*)inParams->ExposureTexture;
//			auto inputBiasColorMask = (ID3D12Resource*)inParams->InputBiasCurrentColorMask;
//			auto transparencyMask = (ID3D12Resource*)inParams->TransparencyMask;
//			auto output = (ID3D12Resource*)inParams->Output;
//
//
//			auto* fsrContext = &deviceContext->FsrContext;
//
//			FfxFsr2DispatchDescription dispatchParameters = {};
//			dispatchParameters.commandList = ffxGetCommandListDX12(((ID3D12GraphicsCommandList*)InCmdList));
//
//			//const float jitterX = 2.0f * inParams->JitterOffsetX / (float)inParams->MVScaleX;
//			//const float jitterY = -2.0f * inParams->JitterOffsetY / (float)inParams->MVScaleY;
//
//			dispatchParameters.jitterOffset.x = inParams->JitterOffsetX;
//			dispatchParameters.jitterOffset.y = inParams->JitterOffsetY;
//
//
//			if (config->DisplayResolution.value_or(false))
//			{
//				dispatchParameters.motionVectorScale.x = (float)inParams->OutWidth;
//				dispatchParameters.motionVectorScale.y = (float)inParams->OutHeight;
//			}
//			else
//			{
//				dispatchParameters.motionVectorScale.x = (float)inParams->MVScaleX;
//				dispatchParameters.motionVectorScale.y = (float)inParams->MVScaleY;
//			}
//
//			dispatchParameters.reset = inParams->ResetRender;
//
//			dispatchParameters.enableSharpening = config->EnableSharpening.value_or(inParams->EnableSharpening);
//
//			if (dispatchParameters.enableSharpening) {
//
//				if (config->Sharpness.has_value())
//				{
//					dispatchParameters.sharpness = config->Sharpness.value();
//				}
//				else
//				{
//					float sharpness = CyberUtil::ConvertSharpness(inParams->Sharpness, config->SharpnessRange);
//					if (sharpness > 0 && sharpness <= 1.0f)
//					{
//						dispatchParameters.sharpness = sharpness;
//					}
//				}
//			}
//			if (InCallback != nullptr)
//				InCallback(20, shouldCancel);
//
//
//
//			//deltatime hax
//			double FrameTimeDeltaInMsec;
//			static double lastFrameTime;
//			double currentTime = CyberUtil::MillisecondsNow();
//			FrameTimeDeltaInMsec = (currentTime - lastFrameTime) * 1000;
//			lastFrameTime = currentTime;
//
//			//const float scalar = CyberFSR::Util::DynaRes(1.0f / 60.0f * 1000, true, FrameTimeDeltaInMsec);
//
//			dispatchParameters.frameTimeDelta = (FrameTimeDeltaInMsec < 1 || FrameTimeDeltaInMsec > 100) ? 7 : FrameTimeDeltaInMsec;
//			//dispatchParameters.frameTimeDelta = inParams->FrameTimeDeltaInMsec;
//
//			dispatchParameters.preExposure = inParams->PreExposure;
//
//			dispatchParameters.renderSize.width = inParams->Width;
//			dispatchParameters.renderSize.height = inParams->Height;
//
//			dispatchParameters.color = ffxGetResourceDX12(fsrContext, color, L"FSR2_InputColor", FFX_RESOURCE_STATE_COMPUTE_READ);
//
//			dispatchParameters.depth = ffxGetResourceDX12(fsrContext, depth, L"FSR2_InputDepth", FFX_RESOURCE_STATE_COMPUTE_READ);
//			dispatchParameters.depth.isDepth = true;
//
//			dispatchParameters.motionVectors = ffxGetResourceDX12(fsrContext, motionVectors, L"FSR2_InputMotionVectors", FFX_RESOURCE_STATE_COMPUTE_READ);
//
//			if (exposureTexture)
//				dispatchParameters.exposure = ffxGetResourceDX12(fsrContext, exposureTexture, L"FSR2_InputExposure", FFX_RESOURCE_STATE_COMPUTE_READ);
//			else
//				dispatchParameters.exposure = (FfxResource)NULL;
//
//			//Not sure if these two actually work
//			FfxFsr2GenerateReactiveDescription genReactive{};
//			if (!config->DisableReactiveMask.value_or(false))
//			{
//				if (inputBiasColorMask)
//				{
//					dispatchParameters.reactive = ffxGetResourceDX12(fsrContext, inputBiasColorMask, L"FSR2_InputReactiveMap", FFX_RESOURCE_STATE_COMPUTE_READ);
//					//dispatchParameters.reactive.description.mipCount = 0;
//				}
//				else
//				{
//					dispatchParameters.reactive = (FfxResource)NULL;
//				}
//
//				if (transparencyMask)
//				{
//					dispatchParameters.transparencyAndComposition = ffxGetResourceDX12(fsrContext, transparencyMask, L"FSR2_TransparencyAndCompositionMap", FFX_RESOURCE_STATE_COMPUTE_READ);
//				}
//				else
//				{
//					dispatchParameters.transparencyAndComposition = (FfxResource)NULL;
//				}
//
//			}
//			//else
//			//{
//			//	//dispatchParameters.reactive = ffxGetResourceDX12(fsrContext, inputBiasColorMask, L"FSR2_InputReactiveMap", FFX_RESOURCE_STATE_COMPUTE_READ);
//			//	//dispatchParameters.reactive = (FfxResource)NULL;
//			//	dispatchParameters.transparencyAndComposition = (FfxResource)NULL;
//			//	genReactive.commandList = ffxGetCommandListDX12(InCmdList);
//			//	genReactive.colorOpaqueOnly = dispatchParameters.depth;
//			//	genReactive.colorPreUpscale = dispatchParameters.color; //???
//			//	genReactive.outReactive = dispatchParameters.reactive;
//			//	genReactive.cutoffThreshold = 1.0;//???
//			//	genReactive.scale = 1.0;//???
//			//	//genReactive.binaryValue = 1.0;//???
//			//	genReactive.renderSize = dispatchParameters.renderSize;//???
//			//	//genReactive.flags = 0b0;//???
//			//	
//			//	
//			//	FfxErrorCode errorCode = ffxFsr2ContextGenerateReactiveMask(fsrContext, &genReactive);
//			//	CyberFSR::Util::FFXErrorCheck(errorCode);
//			//}
//
//			//if (!transparencyMask)
//			//{
//			//	//dispatchParameters.reactive = ffxGetResourceDX12(fsrContext, inputBiasColorMask, L"FSR2_InputReactiveMap", FFX_RESOURCE_STATE_COMPUTE_READ);
//			//	//dispatchParameters.reactive = (FfxResource)NULL;
//			//	//dispatchParameters.transparencyAndComposition = (FfxResource)NULL;
//			//	genReactive.commandList = ffxGetCommandListDX12(InCmdList);
//			//	genReactive.colorOpaqueOnly = dispatchParameters.reactive;
//			//	genReactive.colorPreUpscale = dispatchParameters.color; //???
//			//	genReactive.outReactive = dispatchParameters.reactive;
//			//	genReactive.cutoffThreshold = 1.0;//???
//			//	genReactive.scale = 1.0;//???
//			//	//genReactive.binaryValue = 1.0;//???
//			//	genReactive.renderSize = dispatchParameters.renderSize;//???
//			//	//genReactive.flags = 0b0;//???
//			//
//			//
//			//	FfxErrorCode errorCode = ffxFsr2ContextGenerateReactiveMask(fsrContext, &genReactive);
//			//	CyberFSR::Util::FFXErrorCheck(errorCode);
//			//}
//
//			if (InCallback != nullptr)
//				InCallback(10, shouldCancel);
//
//			dispatchParameters.output = ffxGetResourceDX12(fsrContext, output, L"FSR2_OutputUpscaledColor", FFX_RESOURCE_STATE_UNORDERED_ACCESS);
//
//
//			if (InCallback != nullptr)
//				InCallback(30, shouldCancel);
//
//			//Hax Zone
//			//dispatchParameters.cameraFar = deviceContext->ViewMatrix->GetFarPlane();
//			//dispatchParameters.cameraNear = deviceContext->ViewMatrix->GetNearPlane();
//			//dispatchParameters.cameraFovAngleVertical = DirectX::XMConvertToRadians(deviceContext->ViewMatrix->GetFov());
//			//dispatchParameters.cameraFar = InCmdList->QueryInterface();
//			//dispatchParameters.cameraNear = deviceContext->ViewMatrix->GetNearPlane();
//			//dispatchParameters.cameraFovAngleVertical = DirectX::XMConvertToRadians(deviceContext->ViewMatrix->GetFov());
//
//			if (InCallback != nullptr)
//				InCallback(50, shouldCancel);
//			FfxErrorCode errorCode = ffxFsr2ContextDispatch(fsrContext, &dispatchParameters);
//			CyberFSR::Util::FFXErrorCheck(errorCode);
//
//			((ID3D12GraphicsCommandList*)InCmdList)->SetComputeRootSignature(orgRootSig);
//		}
//#ifdef DEBUG_FEATURES
//		deviceContext->DebugLayer->AddText(L"DLSS2FSR", DirectX::XMFLOAT2(1.0, 1.0));
//		deviceContext->DebugLayer->Render(InCmdList);
//#endif
//
//		myCommandList = ((ID3D12GraphicsCommandList*)InCmdList);
//
//		if (InCallback != nullptr)
//			InCallback(100, shouldCancel);
//	}
//
	return NVSDK_NGX_Result_Success;
}
