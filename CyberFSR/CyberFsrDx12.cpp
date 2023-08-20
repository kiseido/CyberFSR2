#include "pch.h"
#include "Config.h"
#include "CyberFsr.h"
#include "DirectXHooks.h"
#include "Util.h"

#include "DebugOverlay.h"

#ifdef CyberFSR_DO_DX12

//#define CyberFSR_DX12_DUMP

#ifdef _DEBUG
FILE* fDummy;

#endif // _DEBUG

#ifdef CyberFSR_DO_OVERLAY3
	CyberFSROverlay::Overlay overlay;
#endif

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D12_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath,
	ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion,
	unsigned long long unknown0)
{
	CyberLogArgs(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion, unknown0);

#ifdef _DEBUG
	AllocConsole();

	freopen_s(&fDummy, "CONIN$", "r", stdin);
	freopen_s(&fDummy, "CONOUT$", "w", stderr);
	freopen_s(&fDummy, "CONOUT$", "w", stdout);
#endif // _DEBUG


	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Init(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath, ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	CyberLogArgs(InApplicationId, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);

#ifdef _DEBUG
	AllocConsole();

	freopen_s(&fDummy, "CONIN$", "r", stdin);
	freopen_s(&fDummy, "CONOUT$", "w", stderr);
	freopen_s(&fDummy, "CONOUT$", "w", stdout);
#endif // _DEBUG


	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D12_Init_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	CyberLogArgs(InProjectId, InEngineType, InDevice, InEngineVersion, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);

#ifdef _DEBUG
	AllocConsole();

	freopen_s(&fDummy, "CONIN$", "r", stdin);
	freopen_s(&fDummy, "CONOUT$", "w", stderr);
	freopen_s(&fDummy, "CONOUT$", "w", stdout);
#endif // _DEBUG


	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Init_with_ProjectID(const char* InProjectId, NVSDK_NGX_EngineType InEngineType, const char* InEngineVersion, const wchar_t* InApplicationDataPath, ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion)
{
	CyberLogArgs(InProjectId, InEngineType, InEngineVersion, InApplicationDataPath, InDevice, InFeatureInfo, InSDKVersion);

#ifdef _DEBUG
	AllocConsole();

	freopen_s(&fDummy, "CONIN$", "r", stdin);
	freopen_s(&fDummy, "CONOUT$", "w", stderr);
	freopen_s(&fDummy, "CONOUT$", "w", stdout);
#endif // _DEBUG


	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Shutdown(void)
{
	CyberLogArgs();

	CyberFsrContext::instance()->NvParameterInstance->Params.clear();
	CyberFsrContext::instance()->Contexts.clear();
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_Shutdown1(ID3D12Device* InDevice)
{
	CyberLogArgs(InDevice);

	CyberFsrContext::instance()->NvParameterInstance->Params.clear();
	CyberFsrContext::instance()->Contexts.clear();
	return NVSDK_NGX_Result_Success;
}

//currently it's kind of hack but better than what it was previously -- External Memory Tracking
NVSDK_NGX_Result NVSDK_NGX_D3D12_GetParameters(NVSDK_NGX_Parameter** OutParameters)
{
	CyberLogArgs(OutParameters);

	*OutParameters = CyberFsrContext::instance()->NvParameterInstance->AllocateParameters();
	((NvParameter*)*OutParameters)->EvaluateRenderScale();
	return NVSDK_NGX_Result_Success;
}

//currently it's kind of hack still needs a proper implementation 
NVSDK_NGX_Result NVSDK_NGX_D3D12_GetCapabilityParameters(NVSDK_NGX_Parameter** OutParameters)
{
	CyberLogArgs(OutParameters);

	*OutParameters = NvParameter::instance()->AllocateParameters();
	((NvParameter*)*OutParameters)->EvaluateRenderScale();
	return NVSDK_NGX_Result_Success;
}

//currently it's kind of hack still needs a proper implementation
NVSDK_NGX_Result NVSDK_NGX_D3D12_AllocateParameters(NVSDK_NGX_Parameter** OutParameters)
{
	CyberLogArgs(OutParameters);

	*OutParameters = NvParameter::instance()->AllocateParameters();
	return NVSDK_NGX_Result_Success;
}

//currently it's kind of hack still needs a proper implementation
NVSDK_NGX_Result NVSDK_NGX_D3D12_DestroyParameters(NVSDK_NGX_Parameter* InParameters)
{
	CyberLogArgs(InParameters);

	NvParameter::instance()->DeleteParameters((NvParameter*)InParameters);
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetScratchBufferSize(NVSDK_NGX_Feature InFeatureId, const NVSDK_NGX_Parameter* InParameters, size_t* OutSizeInBytes)
{
	CyberLogArgs(InFeatureId, InParameters, OutSizeInBytes);

	*OutSizeInBytes = ffxFsr2GetScratchMemorySizeDX12();
	return NVSDK_NGX_Result_Success;
}

void Fsr2MessageCallback(FfxFsr2MsgType type, const wchar_t* message)
{
	CyberLogArgs(type, message);

	switch (type) {
	case FFX_FSR2_MESSAGE_TYPE_ERROR:
		printf("[ERROR] %ls\n", message);
		break;
	case FFX_FSR2_MESSAGE_TYPE_WARNING:
		printf("[WARNING] %ls\n", message);
		break;
	}

}

NVSDK_NGX_Result NVSDK_NGX_D3D12_CreateFeature(ID3D12GraphicsCommandList* InCmdList, NVSDK_NGX_Feature InFeatureID,
	NVSDK_NGX_Parameter* InParameters, NVSDK_NGX_Handle** OutHandle)
{
	CyberLogArgs(InCmdList, InFeatureID, InParameters, OutHandle);

	const auto inParams = static_cast<const NvParameter*>(InParameters);

	ID3D12Device* device;
	InCmdList->GetDevice(IID_PPV_ARGS(&device));

	auto instance = CyberFsrContext::instance();
	auto& config = instance->MyConfig;
	auto deviceContext = CyberFsrContext::instance()->CreateContext();
	deviceContext->ViewMatrix = ViewMatrixHook::Create(*config);

#ifdef _DEBUG
#ifdef CyberFSR_DO_OVERLAY1
	deviceContext->DebugLayer = std::make_unique<DebugOverlay>();
#endif
#endif

	* OutHandle = &deviceContext->Handle;

	auto initParams = deviceContext->FsrContextDescription;

	const size_t scratchBufferSize = ffxFsr2GetScratchMemorySizeDX12();
	deviceContext->ScratchBuffer = std::vector<unsigned char>(scratchBufferSize);
	auto scratchBuffer = deviceContext->ScratchBuffer.data();

	FfxErrorCode errorCode = ffxFsr2GetInterfaceDX12(&initParams.callbacks, device, scratchBuffer, scratchBufferSize);
	FFX_ASSERT(errorCode == FFX_OK);

	initParams.device = ffxGetDeviceDX12(device);
	initParams.maxRenderSize.width = inParams->renderSizeMax.Width;
	initParams.maxRenderSize.height = inParams->renderSizeMax.Height;
	initParams.displaySize.width = inParams->renderSize.Width;
	initParams.displaySize.height = inParams->renderSize.Height;

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

	HookSetComputeRootSignature(InCmdList);

	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_ReleaseFeature(NVSDK_NGX_Handle* InHandle)
{
	CyberLogArgs(InHandle);

	auto deviceContext = CyberFsrContext::instance()->Contexts[InHandle->Id].get();
	FfxErrorCode errorCode = ffxFsr2ContextDestroy(&deviceContext->FsrContext);
	FFX_ASSERT(errorCode == FFX_OK);
	CyberFsrContext::instance()->DeleteContext(InHandle);
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_D3D12_GetFeatureRequirements(IDXGIAdapter *Adapter, const NVSDK_NGX_FeatureDiscoveryInfo *FeatureDiscoveryInfo, NVSDK_NGX_FeatureRequirement *OutSupported)
{
	CyberLogArgs(Adapter, FeatureDiscoveryInfo, OutSupported);

	*OutSupported = NVSDK_NGX_FeatureRequirement();
	OutSupported->FeatureSupported = NVSDK_NGX_FeatureSupportResult_Supported;
	OutSupported->MinHWArchitecture = 0;
	//Some windows 10 os version
	strcpy_s(OutSupported->MinOSVersion, "10.0.19045.2728");
	return NVSDK_NGX_Result_Success;
}

#ifdef CyberFSR_DX12_DUMP
#include <dxgi1_4.h>
#include <d3d12.h>

std::wofstream outputFile("CyberFSR_Dx12Dump.log");


void DumpCmdListInfo(ID3D12GraphicsCommandList* InCmdList) {
	D3D12_COMMAND_LIST_TYPE cmdListType = InCmdList->GetType();
	outputFile << L"Command List Type: " << (cmdListType == D3D12_COMMAND_LIST_TYPE_DIRECT ? L"DIRECT" :
		cmdListType == D3D12_COMMAND_LIST_TYPE_BUNDLE ? L"BUNDLE" :
		cmdListType == D3D12_COMMAND_LIST_TYPE_COMPUTE ? L"COMPUTE" :
		L"OTHER") << std::endl;
	outputFile.flush();
}

void DumpResourceDetails(ID3D12Resource* resource, const std::string& resourceName) {
	if (resource) {
		D3D12_RESOURCE_DESC desc = resource->GetDesc();
		outputFile << CyberTypes::CyString(resourceName) << L" Details: " << std::endl;
		outputFile << L"  Dimension: " << desc.Dimension << std::endl;
		outputFile << L"  Width: " << desc.Width << std::endl;
		outputFile << L"  Height: " << desc.Height << std::endl;
		outputFile << L"  DepthOrArraySize: " << desc.DepthOrArraySize << std::endl;
		outputFile << L"  Format: " << desc.Format << std::endl;
		// ... any other details you might want
	}
	else {
		outputFile << CyberTypes::CyString(resourceName) << " is NULL" << std::endl;
	}
	outputFile.flush();
}

void DumpDeviceInformation(ID3D12GraphicsCommandList* InCmdList, ID3D12Device* device) {

	// Dump some basic information about the device itself
	D3D12_FEATURE_DATA_D3D12_OPTIONS options = {};
	HRESULT hr = device->CheckFeatureSupport(D3D12_FEATURE_D3D12_OPTIONS, &options, sizeof(options));
	if (SUCCEEDED(hr)) {
		outputFile << L"Resource Binding Tier: " << static_cast<int>(options.ResourceBindingTier) << std::endl;
		outputFile << L"Conservative Rasterization Tier: " << static_cast<int>(options.ConservativeRasterizationTier) << std::endl;
	}
	else {
		outputFile << L"Failed to get D3D12_OPTIONS." << std::endl;
	}

	// Try direct method to get DXGI adapter
	IDXGIAdapter* adapter = nullptr;
	hr = InCmdList->QueryInterface(IID_PPV_ARGS(&adapter));
	if (SUCCEEDED(hr) && adapter) {
		// Get the adapter's description
		DXGI_ADAPTER_DESC desc;
		adapter->GetDesc(&desc);
		outputFile << L"Adapter:" << std::endl;
		outputFile << L"  Description: " << std::wstring(desc.Description) << std::endl;
		outputFile << L"  Dedicated Video Memory: " << desc.DedicatedVideoMemory << L" bytes" << std::endl;
		outputFile << L"  Dedicated System Memory: " << desc.DedicatedSystemMemory << L" bytes" << std::endl;
		outputFile << L"  Shared System Memory: " << desc.SharedSystemMemory << L" bytes" << std::endl;

		adapter->Release();
	}
	else {
		// Create a DXGI Factory to enumerate adapters
		IDXGIFactory4* factory = nullptr;
		hr = CreateDXGIFactory1(IID_PPV_ARGS(&factory));
		if (SUCCEEDED(hr) && factory) {
			IDXGIAdapter* adapter = nullptr;
			for (UINT i = 0; factory->EnumAdapters(i, &adapter) != DXGI_ERROR_NOT_FOUND; ++i) {
				// Get the adapter's description
				DXGI_ADAPTER_DESC desc;
				adapter->GetDesc(&desc);
				outputFile << L"Adapter:" << std::endl;
				outputFile << L"  Description: " << std::wstring(desc.Description) << std::endl;
				outputFile << L"  Dedicated Video Memory: " << desc.DedicatedVideoMemory << L" bytes" << std::endl;
				outputFile << L"  Dedicated System Memory: " << desc.DedicatedSystemMemory << L" bytes" << std::endl;
				outputFile << L"  Shared System Memory: " << desc.SharedSystemMemory << L" bytes" << std::endl;

				adapter->Release();
			}
			factory->Release();
		}
		else {
			outputFile << L"Failed to create DXGI factory or enumerate adapters." << std::endl;
		}
	}

	// ... Add more dumps as needed ...

	outputFile.flush();
}

#endif 


NVSDK_NGX_Result NVSDK_NGX_D3D12_EvaluateFeature(ID3D12GraphicsCommandList* InCmdList, const NVSDK_NGX_Handle* InFeatureHandle, const NVSDK_NGX_Parameter* InParameters, PFN_NVSDK_NGX_ProgressCallback InCallback)
{
	CyberLogArgs(InCmdList, InFeatureHandle, InParameters, InCallback);

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
	auto instance = CyberFsrContext::instance();
	auto& config = instance->MyConfig;
	auto deviceContext = CyberFsrContext::instance()->Contexts[InFeatureHandle->Id].get();



	if (orgRootSig)
	{
		const auto inParams = static_cast<const NvParameter*>(InParameters);

#ifdef CyberFSR_DX12_DUMP
		if (device) {
			DumpDeviceInformation(InCmdList, device);
			DumpCmdListInfo(InCmdList);
			DumpResourceDetails((ID3D12Resource*)inParams->Color, "Color");
			DumpResourceDetails((ID3D12Resource*)inParams->Depth, "Depth");
			DumpResourceDetails((ID3D12Resource*)inParams->MotionVectors, "MotionVectors");
			DumpResourceDetails((ID3D12Resource*)inParams->ExposureTexture, "Exposure");
			//device->Release();
		}
#endif

		auto* fsrContext = &deviceContext->FsrContext;

		FfxFsr2DispatchDescription dispatchParameters = {};

		dispatchParameters.commandList = ffxGetCommandListDX12(InCmdList);

		dispatchParameters.color = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->Color, (wchar_t*)L"FSR2_InputColor");
		dispatchParameters.depth = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->Depth, (wchar_t*)L"FSR2_InputDepth");

		dispatchParameters.motionVectors = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->MotionVectors, (wchar_t*)L"FSR2_InputMotionVectors");

		if (!config->AutoExposure)
			dispatchParameters.exposure = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->ExposureTexture, (wchar_t*)L"FSR2_InputExposure");
		/*
		if (inParams->InputBiasCurrentColorMask == nullptr && inParams->InputBiasCurrentColorMask == nullptr) {
			// Enable automatic generation of the Reactive mask and Transparency & composition mask
			dispatchParameters.enableAutoReactive = true;

			// TODO: Provide the correct opaque-only portion of the backbuffer. For now, this is an imitation.
			dispatchParameters.colorOpaqueOnly = dispatchParameters.color;

			// Set the required values for the automatic generation feature
			dispatchParameters.autoTcThreshold = 0.05f;  // Recommended default value
			dispatchParameters.autoTcScale = 1.0f;      // Recommended default value
			dispatchParameters.autoReactiveScale = 5.00f;  // Recommended default value
			dispatchParameters.autoReactiveMax = 0.90f;  // Recommended default value
		}
		else 
		*/
		if (!config->DisableReactiveMask.has_value() || (config->DisableReactiveMask.has_value() && (config->DisableReactiveMask.value() == false)))
		{
			if (inParams->InputBiasCurrentColorMask != nullptr) {
				dispatchParameters.reactive = ffxGetResourceDX12(fsrContext, nullptr, L"FSR2_EmptyInputReactiveMap");

				dispatchParameters.colorOpaqueOnly = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->InputBiasCurrentColorMask, L"FSR2_InputReactiveMap");

				dispatchParameters.enableAutoReactive = true;

				// Set the required values for the automatic generation feature
				dispatchParameters.autoTcThreshold = 0.01f;  // Recommended default value 0.05f
				dispatchParameters.autoTcScale = 1.0f;      // Recommended default value 1.00
				dispatchParameters.autoReactiveScale = 10.00f;  // Recommended default value 5.00
				dispatchParameters.autoReactiveMax = 0.50f;  // Recommended default value 0.90
			}
			else {
				dispatchParameters.reactive = ffxGetResourceDX12(fsrContext, nullptr, L"FSR2_EmptyInputReactiveMap");
			}

			if (inParams->TransparencyMask != nullptr) {
				dispatchParameters.transparencyAndComposition = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->TransparencyMask, L"FSR2_TransparencyAndCompositionMap");
			}
			else {
				dispatchParameters.transparencyAndComposition = ffxGetResourceDX12(fsrContext, nullptr, L"FSR2_EmptyTransparencyAndCompositionMap");
			}
		}
		else {

			dispatchParameters.reactive = ffxGetResourceDX12(fsrContext, nullptr, L"FSR2_EmptyInputReactiveMap");
			dispatchParameters.transparencyAndComposition = ffxGetResourceDX12(fsrContext, nullptr, L"FSR2_EmptyTransparencyAndCompositionMap");
			/*
			// Enable automatic generation of the Reactive mask and Transparency & composition mask
			dispatchParameters.enableAutoReactive = true;

			// Set the required values for the automatic generation feature
			dispatchParameters.autoTcThreshold = 0.01f;  // Recommended default value
			dispatchParameters.autoTcScale = 1.0f;      // Recommended default value
			dispatchParameters.autoReactiveScale = 10.00f;  // Recommended default value
			dispatchParameters.autoReactiveMax = 0.50f;  // Recommended default value
			*/
		}

		dispatchParameters.output = ffxGetResourceDX12(fsrContext, (ID3D12Resource*)inParams->Output, (wchar_t*)L"FSR2_OutputUpscaledColor", FFX_RESOURCE_STATE_UNORDERED_ACCESS);

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
		dispatchParameters.renderSize.width = inParams->renderSize.Width;
		dispatchParameters.renderSize.height = inParams->renderSize.Height;

		

		//Hax Zone
		/*
		auto low = deviceContext->ViewMatrix->GetFarPlane();
		auto high = deviceContext->ViewMatrix->GetNearPlane();

		if (low > high) {
			auto temp = low;
			high = low;
			low = temp;
		}

		CyberLogArgs(deltaTime, low, high);

		dispatchParameters.cameraFar = high;
		dispatchParameters.cameraNear = low;
		*/
		dispatchParameters.cameraFovAngleVertical = DirectX::XMConvertToRadians(deviceContext->ViewMatrix->GetFov());

		FfxErrorCode errorCode = ffxFsr2ContextDispatch(fsrContext, &dispatchParameters);

		FFX_ASSERT(errorCode == FFX_OK);

		InCmdList->SetComputeRootSignature(orgRootSig);
	}

#ifdef CyberFSR_DO_OVERLAY1
	//deviceContext->DebugLayer->AddText(L"DLSS2FSR", DirectX::XMFLOAT2(1.0, 1.0));
	deviceContext->DebugLayer->Render();
#endif // CyberFSR_DO_OVERLAY

#ifdef CyberFSR_DO_OVERLAY2
	if (CyberFSROverlay::overlay == nullptr) {
		CyberFSROverlay::overlay = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CyberFSROverlay::DisplayTimeOnWindow, NULL, 0, NULL);
	}
#endif

#ifdef CyberFSR_DO_OVERLAY3
	overlay.setupWindowDX(InCmdList);
#endif

	myCommandList = InCmdList;

	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_UpdateFeature(const NVSDK_NGX_Application_Identifier *ApplicationId, const NVSDK_NGX_Feature FeatureID)
{
	CyberLogArgs(ApplicationId, FeatureID);
	return NVSDK_NGX_Result_Success;
}

#endif //  #define CyberFSR_DO_DX12