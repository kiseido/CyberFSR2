#include "pch.h"
#include "Config.h"
#include "CyberFsr.h"
#include "DirectXHooks.h"
#include "Util.h"

// Declare a struct to hold the fence and event objects
struct FenceInfo
{
    ID3D12Fence* fence;
    HANDLE fenceEvent;
};

// Define the missing function and variable declarations
void Fsr2MessageCallback(FfxFsr2MsgType type, const wchar_t* message)
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

NVSDK_NGX_Result NVSDK_NGX_D3D11_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
    return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D11_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath,
    ID3D11Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion,
    unsigned long long unknown0)
{
#ifdef _DEBUG
    AllocConsole();
    FILE* fDummy;
    freopen_s(&fDummy, "CONIN$", "r", stdin);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
#endif // _DEBUG

    return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_Shutdown(void)
{
    CyberFsrContext::instance()->NvParameterInstance->Params.clear();
    CyberFsrContext::instance()->Contexts.clear();
    return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_GetParameters(NVSDK_NGX_Parameter** OutParameters)
{
    *OutParameters = CyberFsrContext::instance()->NvParameterInstance->AllocateParameters();
    return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId, const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes)
{
    *OutSizeInBytes = ffxFsr2GetScratchMemorySizeDX12();
    return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_CreateFeature(ID3D11Device* InDevice, NVSDK_NGX_Feature InFeatureID, NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
    const auto inParams = static_cast<const NvParameter*>(InParameters);

    auto instance = CyberFsrContext::instance();
    auto& config = instance->MyConfig;
    auto deviceContext = instance->CreateContext();
    deviceContext->ViewMatrix = ViewMatrixHook::Create(*config);
#ifdef DEBUG_FEATURES
    deviceContext->DebugLayer = std::make_unique<DebugOverlay>(device, InCmdList);
#endif

    * OutHandle = &deviceContext->Handle;

    auto initParams = deviceContext->FsrContextDescription;

    const size_t scratchBufferSize = ffxFsr2GetScratchMemorySizeDX12();
    deviceContext->ScratchBuffer = std::vector<unsigned char>(scratchBufferSize);
    auto scratchBuffer = deviceContext->ScratchBuffer.data();

    FfxErrorCode errorCode = ffxFsr2GetInterfaceDX12(&initParams.callbacks, dx12InDevice, scratchBuffer, scratchBufferSize);
    FFX_ASSERT(errorCode == FFX_OK);

    initParams.device = ffxGetDeviceDX12(dx12InDevice);
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
    initParams.fpMessage = Fsr2MessageCallback;
#endif // DEBUG

    errorCode = ffxFsr2ContextCreate(&deviceContext->FsrContext, &initParams);
    FFX_ASSERT(errorCode == FFX_OK);

    // Create a fence and event object for synchronization
    FenceInfo* fenceInfo = new FenceInfo();
    InDevice->QueryInterface(IID_PPV_ARGS(&fenceInfo->fence));
    fenceInfo->fenceEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

    // Associate the fence info with the feature handle
    deviceContext->Handle.UserData = fenceInfo;

    return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_ReleaseFeature(NVSDK_NGX_Handle* InHandle)
{
    auto deviceContext = CyberFsrContext::instance()->Contexts[InHandle->Id].get();

    // Retrieve the associated fence info
    FenceInfo* fenceInfo = static_cast<FenceInfo*>(deviceContext->Handle.UserData);

    // Wait for the GPU to complete all previous commands
    fenceInfo->fence->SetEventOnCompletion(1, fenceInfo->fenceEvent);
    WaitForSingleObject(fenceInfo->fenceEvent, INFINITE);

    // Release the fence and event objects
    fenceInfo->fence->Release();
    CloseHandle(fenceInfo->fenceEvent);
    delete fenceInfo;

    FfxErrorCode errorCode = ffxFsr2ContextDestroy(&deviceContext->FsrContext);
    FFX_ASSERT(errorCode == FFX_OK);
    CyberFsrContext::instance()->DeleteContext(InHandle);

    return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D11_EvaluateFeature(ID3D11Device* InDevice, ID3D11DeviceContext* InDeviceContext, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
    auto device = InDevice;
    auto deviceContext = CyberFsrContext::instance()->Contexts[InFeatureHandle->Id].get();

    const auto inParams = static_cast<const NvParameter*>(InParameters);
    auto* fsrContext = &deviceContext->FsrContext;

    FfxFsr2DispatchDescription dispatchParameters = {};
    dispatchParameters.commandList = ffxGetCommandListDX12(deviceContext->CommandList);
    dispatchParameters.color = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->Color, "FSR2_InputColor");
    dispatchParameters.depth = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->Depth, "FSR2_InputDepth");
    dispatchParameters.motionVectors = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->MotionVectors, "FSR2_InputMotionVectors");
    if (!config->AutoExposure)
        dispatchParameters.exposure = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->ExposureTexture, "FSR2_InputExposure");

    // ... (rest of the dispatchParameters setup)

    // Create a fence and event object for synchronization
    FenceInfo* fenceInfo = new FenceInfo();
    InDeviceContext->QueryInterface(IID_PPV_ARGS(&fenceInfo->fence));
    fenceInfo->fenceEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

    // Associate the fence info with the feature handle
    deviceContext->Handle.UserData = fenceInfo;

    // Issue the GPU command to evaluate the feature
    ffxFsr2ContextDispatch(fsrContext, &dispatchParameters);

    // Signal the fence after the GPU command is completed
    fenceInfo->fence->SetEventOnCompletion(1, fenceInfo->fenceEvent);

    // Pass the fence handle to the callback function for progress tracking
    InCallback(InFeatureHandle->Id, fenceInfo->fenceEvent);

    return NVSDK_NGX_Result_Success;
}
