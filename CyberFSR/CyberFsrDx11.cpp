#include "pch.h"
#include "Config.h"
#include "CyberFsr.h"
#include "Util.h"

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D11_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath,
	ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion,
	unsigned long long unknown0)
{
    auto currentTime = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(currentTime - startTime).count();
}

// Helper function to write the function name and CPU tick to the log file
void logFunctionCall(const std::string& functionName)
{
    std::lock_guard<std::mutex> lock(logMutex); // Lock the mutex

    // Open the log file if it is not already open
    if (!logFile.is_open())
    {
        logFile.open("debug.log", std::ios::app); // Open in append mode
    }

    if (logFile.is_open())
    {
        logFile << functionName << " " << getTick() << std::endl;
    }
}

// Helper macro to simplify logging function calls
#define LOG_FUNCTION_CALL() logFunctionCall(__func__)

#endif // SaveToLog

#include "Logging.h"


struct FenceInfo
{
    ID3D12Fence* fence;
    HANDLE fenceEvent;
};

std::map<const NVSDK_NGX_Handle*, FenceInfo*> syncObjects;

void dx11Fsr2MessageCallback(FfxFsr2MsgType type, const wchar_t* message)
{
    CyberLOG();

    switch (type) {
    case FFX_FSR2_MESSAGE_TYPE_ERROR:
        printf("[ERROR] %ls\n", message);
        break;
    case FFX_FSR2_MESSAGE_TYPE_WARNING:
        printf("[WARNING] %ls\n", message);
        break;
    }
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	return NVSDK_NGX_D3D11_Init_Ext(0x1337, InApplicationDataPath, nullptr, InFeatureInfo, InSDKVersion, 0);
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	return NVSDK_NGX_D3D11_Init_Ext(0x1337, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, 0);
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_Init_with_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	return NVSDK_NGX_D3D11_Init_Ext(0x1337, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, 0);
}



NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Shutdown(void)
{
	CyberFsrContext::instance()->NvParameterInstance->Params.clear();
	CyberFsrContext::instance()->Contexts.clear();
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Shutdown1(ID3D11Device* InDevice)
{
	return NVSDK_NGX_D3D11_Shutdown();
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Shutdown1(ID3D11Device* InDevice)
{
#ifdef SaveToLog
	LOG_FUNCTION_CALL();
#endif // SaveToLog

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
	*OutParameters = CyberFsrContext::instance()->NvParameterInstance->AllocateParameters();
	return NVSDK_NGX_Result_Success;
}

//currently it's kind of hack still needs a proper implementation 
NVSDK_NGX_Result NVSDK_NGX_D3D11_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters)
{
	*OutParameters = NvParameter::instance()->AllocateParameters();
	return NVSDK_NGX_Result_Success;
}

//currently it's kind of hack still needs a proper implementation
NVSDK_NGX_Result NVSDK_NGX_D3D11_AllocateParameters(NVSDK_NGX_Parameter** OutParameters)
{
	*OutParameters = NvParameter::instance()->AllocateParameters();
	return NVSDK_NGX_Result_Success;
}

//currently it's kind of hack still needs a proper implementation
NVSDK_NGX_Result NVSDK_NGX_D3D11_DestroyParameters(NVSDK_NGX_Parameter* InParameters)
{
	NvParameter::instance()->DeleteParameters((NvParameter*)InParameters);
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId,
	const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes)
{
	*OutSizeInBytes = ffxFsr2GetScratchMemorySizeDX11();
	return NVSDK_NGX_Result_Success;
}

void Fsr2MessageCallback_DX11(FfxFsr2MsgType type, const wchar_t* message)
{
	switch (type) {
	case FFX_FSR2_MESSAGE_TYPE_ERROR:
		printf("[ERROR] %ls\n", message);
		break;
	case FFX_FSR2_MESSAGE_TYPE_WARNING:
		printf("[WARNING] %ls\n", message);
		break;
	}

}

NVSDK_NGX_Result NVSDK_NGX_D3D11_CreateFeature(ID3D11DeviceContext* InDevCtx, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
	const auto inParams = static_cast<const NvParameter*>(InParameters);

	ID3D11Device* device;
	InDevCtx->GetDevice(&device);

	auto instance = CyberFsrContext::instance();
	auto& config = instance->MyConfig;
	auto deviceContext = CyberFsrContext::instance()->CreateContext();
	deviceContext->ViewMatrix = ViewMatrixHook::Create(*config);
#ifdef DEBUG_FEATURES
	deviceContext->DebugLayer = std::make_unique<DebugOverlay>(device, InCmdList);
#endif

	* OutHandle = &deviceContext->Handle;

	auto initParams = deviceContext->FsrContextDescription;

	const size_t scratchBufferSize = ffxFsr2GetScratchMemorySizeDX11();
	deviceContext->ScratchBuffer = std::vector<unsigned char>(scratchBufferSize);
	auto scratchBuffer = deviceContext->ScratchBuffer.data();

	FfxErrorCode errorCode = ffxFsr2GetInterfaceDX11(&initParams.callbacks, device, scratchBuffer, scratchBufferSize);
	FFX_ASSERT(errorCode == FFX_OK);

	initParams.device = ffxGetDeviceDX11(device);
	initParams.maxRenderSize.width = inParams->Width;
	initParams.maxRenderSize.height = inParams->Height;
	initParams.displaySize.width = inParams->OutWidth;
	initParams.displaySize.height = inParams->OutHeight;

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
	if (config->InfiniteFarPlane.value_or(false))
	{
		initParams.flags |= FFX_FSR2_ENABLE_DEPTH_INFINITE;
	}

#ifdef _DEBUG
	initParams.flags |= FFX_FSR2_ENABLE_DEBUG_CHECKING;
	initParams.fpMessage = Fsr2MessageCallback_DX11;
#endif // DEBUG

	errorCode = ffxFsr2ContextCreate(&deviceContext->FsrContext, &initParams);
	FFX_ASSERT(errorCode == FFX_OK);

    const size_t scratchBufferSize = ffxFsr2GetScratchMemorySizeDX12();
    deviceContext->ScratchBuffer = std::vector<unsigned char>(scratchBufferSize);
    auto scratchBuffer = deviceContext->ScratchBuffer.data();

NVSDK_NGX_Result NVSDK_NGX_D3D11_ReleaseFeature(NVSDK_NGX_Handle* InHandle)
{
	auto deviceContext = CyberFsrContext::instance()->Contexts[InHandle->Id].get();
	FfxErrorCode errorCode = ffxFsr2ContextDestroy(&deviceContext->FsrContext);
	FFX_ASSERT(errorCode == FFX_OK);
	CyberFsrContext::instance()->DeleteContext(InHandle);
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_GetFeatureRequirements(IDXGIAdapter* Adapter, const NVSDK_NGX_FeatureDiscoveryInfo* FeatureDiscoveryInfo, NVSDK_NGX_FeatureRequirement* OutSupported)
{
	*OutSupported = NVSDK_NGX_FeatureRequirement();
	OutSupported->FeatureSupported = NVSDK_NGX_FeatureSupportResult_Supported;
	OutSupported->MinHWArchitecture = 0;
	//Some windows 10 os version
	strcpy_s(OutSupported->MinOSVersion, "10.0.19045.2728");
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_EvaluateFeature(ID3D11Device* InDevice, ID3D11DeviceContext* InDeviceContext, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
	ID3D11Device* device;
	InDevCtx->GetDevice(&device);
	auto instance = CyberFsrContext::instance();
	auto& config = instance->MyConfig;
	auto deviceContext = CyberFsrContext::instance()->Contexts[InFeatureHandle->Id].get();

	const auto inParams = static_cast<const NvParameter*>(InParameters);

	auto* fsrContext = &deviceContext->FsrContext;

	FfxFsr2DispatchDescription dispatchParameters = {};
	dispatchParameters.commandList = InDevCtx;
	auto motionVectors = (ID3D11Resource*)inParams->MotionVectors;
	auto color = (ID3D11Resource*)inParams->Color;
	dispatchParameters.color = ffxGetResourceDX11(fsrContext, color, (wchar_t*)L"FSR2_InputColor");
	dispatchParameters.depth = ffxGetResourceDX11(fsrContext, (ID3D11Resource*)inParams->Depth, (wchar_t*)L"FSR2_InputDepth");
	dispatchParameters.motionVectors = ffxGetResourceDX11(fsrContext, motionVectors, (wchar_t*)L"FSR2_InputMotionVectors");
	if (!config->AutoExposure)
		dispatchParameters.exposure = ffxGetResourceDX11(fsrContext, (ID3D11Resource*)inParams->ExposureTexture, (wchar_t*)L"FSR2_InputExposure");

	//Not sure if these two actually work
	if (!config->DisableReactiveMask.value_or(false))
	{
		dispatchParameters.reactive = ffxGetResourceDX11(fsrContext, (ID3D11Resource*)inParams->InputBiasCurrentColorMask, (wchar_t*)L"FSR2_InputReactiveMap");
		dispatchParameters.transparencyAndComposition = ffxGetResourceDX11(fsrContext, (ID3D11Resource*)inParams->TransparencyMask, (wchar_t*)L"FSR2_TransparencyAndCompositionMap");
	}

	dispatchParameters.output = ffxGetResourceDX11(fsrContext, (ID3D11Resource*)inParams->Output, (wchar_t*)L"FSR2_OutputUpscaledColor", FFX_RESOURCE_STATE_UNORDERED_ACCESS);

	dispatchParameters.jitterOffset.x = inParams->JitterOffsetX;
	dispatchParameters.jitterOffset.y = inParams->JitterOffsetY;

	dispatchParameters.motionVectorScale.x = (float)inParams->MVScaleX;
	dispatchParameters.motionVectorScale.y = (float)inParams->MVScaleY;

	dispatchParameters.reset = inParams->ResetRender;

	float sharpness = Util::ConvertSharpness(inParams->Sharpness, config->SharpnessRange);
	dispatchParameters.enableSharpening = config->EnableSharpening.value_or(inParams->EnableSharpening);
	dispatchParameters.sharpness = config->Sharpness.value_or(sharpness);

	//deltatime hax
	static double lastFrameTime;
	double currentTime = Util::MillisecondsNow();
	double deltaTime = (currentTime - lastFrameTime);
	lastFrameTime = currentTime;

	dispatchParameters.frameTimeDelta = (float)deltaTime;
	dispatchParameters.preExposure = 1.0f;
	dispatchParameters.renderSize.width = inParams->Width;
	dispatchParameters.renderSize.height = inParams->Height;

	//Hax Zone
	dispatchParameters.cameraFar = deviceContext->ViewMatrix->GetFarPlane();
	dispatchParameters.cameraNear = deviceContext->ViewMatrix->GetNearPlane();
	dispatchParameters.cameraFovAngleVertical = DirectX::XMConvertToRadians(deviceContext->ViewMatrix->GetFov());
	FfxErrorCode errorCode = ffxFsr2ContextDispatch(fsrContext, &dispatchParameters);
	FFX_ASSERT(errorCode == FFX_OK);

#ifdef DEBUG_FEATURES
	deviceContext->DebugLayer->AddText(L"DLSS2FSR", DirectX::XMFLOAT2(1.0, 1.0));
	deviceContext->DebugLayer->Render(InCmdList);
#endif

    ID3D11DeviceChild* orgRootSig = nullptr;

    auto device = InDevice;
    auto deviceContext = CyberFsrContext::instance()->Contexts[InFeatureHandle->Id].get();

    auto instance = CyberFsrContext::instance();
    auto& config = instance->MyConfig;

    const auto inParams = static_cast<const NvParameter*>(InParameters);
    auto* fsrContext = &deviceContext->FsrContext;

    FfxFsr2DispatchDescription dispatchParameters = {};
    ID3D11DeviceContext* dx11DeviceContext = static_cast<ID3D11DeviceContext*>(InDeviceContext);
    ID3D11CommandList* commandList = nullptr;
    dx11DeviceContext->FinishCommandList(FALSE, &commandList);

    dispatchParameters.commandList = commandList;

    rootSigMutex.lock();
    if (commandListVector.contains((ID3D12GraphicsCommandList*)commandList))
    {
        orgRootSig = (ID3D11DeviceChild*)commandListVector[(ID3D12GraphicsCommandList*)commandList];
    }
    else
    {
        printf("Cant find the RootSig\n");
    }
    rootSigMutex.unlock();
    if (orgRootSig) {
        //dispatchParameters.commandList = ffxGetCommandListDX12(InDeviceContext);
        dispatchParameters.color = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->Color, (wchar_t*)L"FSR2_InputColor");
        dispatchParameters.depth = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->Depth, (wchar_t*)L"FSR2_InputDepth");
        dispatchParameters.motionVectors = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->MotionVectors, (wchar_t*)L"FSR2_InputMotionVectors");
        if (!config->AutoExposure)
            dispatchParameters.exposure = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->ExposureTexture, (wchar_t*)L"FSR2_InputExposure");

        // ... (rest of the dispatchParameters setup)

        // Retrieve the associated fence info
        FenceInfo* fenceInfo = syncObjects[InFeatureHandle];

        // Issue the GPU command to evaluate the feature
        ffxFsr2ContextDispatch(fsrContext, &dispatchParameters);

        // Signal the fence after the GPU command is completed
        fenceInfo->fence->SetEventOnCompletion(1, fenceInfo->fenceEvent);

        // Pass the fence handle to the callback function for progress tracking
        float progress = 0;
        bool shouldcancel = false;
        InCallback(progress, shouldcancel);
    }

#ifdef DEBUG_FEATURES
    deviceContext->DebugLayer->AddText(L"DLSS2FSR DX11", DirectX::XMFLOAT2(1.0, 1.0));
    deviceContext->DebugLayer->Render(InCmdList);
#endif

    return NVSDK_NGX_Result_Success;
}


// dx 12 - > dx11 interop https://learn.microsoft.com/en-us/windows/win32/direct3d12/direct3d-12-with-direct3d-11--direct-2d-and-gdi

// external\FidelityFX-FSR2\src\ffx-fsr2-api\ffx_fsr2_interface.h
// external\nvngx_dlss_sdk\include\nvsdk_ngx_defs.h
// external\nvngx_dlss_sdk\include\nvsdk_ngx_helpers.h



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

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D11_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
    CyberLOG();

    // InFeatureInfo has important info!!!?!

    auto output = NVSDK_NGX_Result_Success;

    return output;
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_Shutdown1(ID3D11Device* InDevice)
{
    CyberLOG();

    return NVSDK_NGX_Result_Success;
}


//TODO External Memory Tracking
NVSDK_NGX_Result NVSDK_NGX_D3D11_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters)
{
    CyberLOG();

    return NVSDK_NGX_Result_Success;
}

//TODO
NVSDK_NGX_Result NVSDK_NGX_D3D11_AllocateParameters(NVSDK_NGX_Parameter** OutParameters)
{
    CyberLOG();

    return NVSDK_NGX_Result_Success;
}

//TODO
NVSDK_NGX_Result NVSDK_NGX_D3D11_DestroyParameters(NVSDK_NGX_Parameter* InParameters)
{
    CyberLOG();

    return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_D3D11_CreateFeature(ID3D11DeviceContext* InDevCtx, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
    CyberLOG();

    NVSDK_NGX_Result output = NVSDK_NGX_Result_Fail;

    return output;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_EvaluateFeature(ID3D11DeviceContext* InDevCtx, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
    CyberLOG();

    return NVSDK_NGX_Result_Success;
}