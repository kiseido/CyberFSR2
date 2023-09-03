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

struct D3DCyberFSRRenderTask {

	const NvParameter* parameter;

	FfxFsr2Context* fsr2context;

	FeatureContext* CyberFSRContext;

	ID3D12GraphicsCommandList* commandList;

	ID3D12Device* device;

	DLSSResources<ID3D12Resource*> resources_inputs;

	DLSSResources<ID3D12Resource*> resources_copies;

	DLSSResources<D3D12_RESOURCE_DESC> resources_descs;

	struct HeapHolder {
		D3D12_HEAP_DESC desc;
		ID3D12Heap* heap_p;
	} heapHolder;


	FfxFsr2DispatchDescription dispatchParameters{};

	bool DisplayResolution = false;

	bool AutoExposure = false;

	bool HDR = false;
	bool JitterCancellation = false;
	bool DepthInverted = false;

	bool EnableSharpening = false;

	bool InfiniteFarPlane = false;

	float FarPlane = -2.0;
	float NearPlane = -2.0;
	float VerticalFOV = -2.0;

	float Sharpness = -2.0;

	float PreExposure = 1.0;

	float FrameTimeDelta = 0;

	ReactiveMaskState ReactiveMaskType = Game_Defined;

	D3DCyberFSRRenderTask();

	void setup();
	void doFSR2();
	void end();
private:
	void setupHeap();
	void CopyContents(ID3D12Resource* source, ID3D12Resource* destination);

	void DuplicateAllResources();
	void CopyAllResourceContents();

	ID3D12Resource* GetNewAlignedResourceWithClonedProperties(D3D12_RESOURCE_DESC& desc, ID3D12Resource* source);
};

void D3DCyberFSRRenderTask::CopyAllResourceContents() {
	static constexpr size_t NUM_RESOURCES = resources_copies.length; // Based on the number of members in DLSSResources

	for (size_t i = NUM_RESOURCES; i > 0; i--) {
		CopyContents(resources_inputs[i - 1], resources_copies[i - 1]);
	}
}

void D3DCyberFSRRenderTask::DuplicateAllResources() {
	static constexpr size_t NUM_RESOURCES = resources_copies.length; // Based on the number of members in DLSSResources

	for (size_t i = NUM_RESOURCES; i > 0; i--) {
		CopyContents(resources_copies[i - 1], resources_inputs[i - 1]);
	}
}

D3DCyberFSRRenderTask::D3DCyberFSRRenderTask(){
	//deltatime hax
	static double lastFrameTime = Util::MillisecondsNow();
	double currentTime = Util::MillisecondsNow();
	FrameTimeDelta = (currentTime - lastFrameTime);
	lastFrameTime = currentTime;
}


void D3DCyberFSRRenderTask::CopyContents(ID3D12Resource* source, ID3D12Resource* destination) {
	if (source == nullptr || destination == nullptr) {
		// Handle error - either source or destination is invalid.
		return;
	}

	D3D12_RESOURCE_BARRIER barrierDescs[2] = {};

	// Transition source to copy source state
	barrierDescs[0].Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
	barrierDescs[0].Flags = D3D12_RESOURCE_BARRIER_FLAG_NONE;
	barrierDescs[0].Transition.pResource = source;
	barrierDescs[0].Transition.StateBefore = D3D12_RESOURCE_STATE_COMMON; // Assuming initial state is COMMON, adjust as needed
	barrierDescs[0].Transition.StateAfter = D3D12_RESOURCE_STATE_COPY_SOURCE;
	barrierDescs[0].Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;

	// Transition destination to copy dest state
	barrierDescs[1].Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
	barrierDescs[1].Flags = D3D12_RESOURCE_BARRIER_FLAG_NONE;
	barrierDescs[1].Transition.pResource = destination;
	barrierDescs[1].Transition.StateBefore = D3D12_RESOURCE_STATE_COMMON; // Assuming initial state is COMMON, adjust as needed
	barrierDescs[1].Transition.StateAfter = D3D12_RESOURCE_STATE_COPY_DEST;
	barrierDescs[1].Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;

	commandList->ResourceBarrier(2, barrierDescs);

	// Execute the copy
	commandList->CopyResource(destination, source);

	// If you want to transition the resources back to a different state after copying, 
	// you can add another set of barriers here. For now, I'll assume we're leaving 
	// them in the copy states.
}


inline ID3D12Resource* D3DCyberFSRRenderTask::GetNewAlignedResourceWithClonedProperties(D3D12_RESOURCE_DESC& desc, ID3D12Resource* source) {
	if (source == nullptr)
		return nullptr;

	D3D12_RESOURCE_DESC resourceDesc = source->GetDesc();
	

	desc.Dimension = resourceDesc.Dimension;
	desc.Alignment = D3D12_DEFAULT_MSAA_RESOURCE_PLACEMENT_ALIGNMENT;
	desc.Width = resourceDesc.Width;
	desc.Height = resourceDesc.Height;
	desc.DepthOrArraySize = resourceDesc.DepthOrArraySize;
	desc.MipLevels = resourceDesc.MipLevels;
	desc.Format = resourceDesc.Format; // Adjust format as needed
	desc.SampleDesc.Count = resourceDesc.SampleDesc.Count;
	desc.SampleDesc.Quality = resourceDesc.SampleDesc.Quality;
	desc.Layout = resourceDesc.Layout;
	desc.Flags = resourceDesc.Flags; // Adjust flags as needed

	ID3D12Resource* resource_p;

	HRESULT hr = device->CreatePlacedResource(heapHolder.heap_p, 0, &desc, D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE, nullptr, IID_PPV_ARGS(&resource_p));
	if (FAILED(hr)) {
		// Handle error
		return nullptr;
	}

	return resource_p;
}

void D3DCyberFSRRenderTask::setup() {
	// make a copy of and buffer present
	setupHeap();
	DuplicateAllResources();
	CopyAllResourceContents();
}

void D3DCyberFSRRenderTask::setupHeap() {
	// Create the heap
	heapHolder.desc.SizeInBytes = 0; // Set the size to 0 to let the runtime determine the size.
	heapHolder.desc.Properties.Type = D3D12_HEAP_TYPE_DEFAULT;
	heapHolder.desc.Properties.CPUPageProperty = D3D12_CPU_PAGE_PROPERTY_UNKNOWN;
	heapHolder.desc.Properties.MemoryPoolPreference = D3D12_MEMORY_POOL_UNKNOWN;
	heapHolder.desc.Properties.CreationNodeMask = 1;
	heapHolder.desc.Properties.VisibleNodeMask = 1;
	heapHolder.desc.Alignment = D3D12_DEFAULT_MSAA_RESOURCE_PLACEMENT_ALIGNMENT;

	HRESULT hr = device->CreateHeap(&heapHolder.desc, IID_PPV_ARGS(&heapHolder.heap_p));
	if (FAILED(hr)) {
		// Handle error
		return;
	}
}

void D3DCyberFSRRenderTask::doFSR2() {
	// do FSR2 dispatch
	dispatchParameters.commandList = ffxGetCommandListDX12(commandList);

	dispatchParameters.color = ffxGetResourceDX12(fsr2context, resources_copies.getColor(), (wchar_t*)L"FSR2_InputColor");
	dispatchParameters.depth = ffxGetResourceDX12(fsr2context, resources_copies.getDepth(), (wchar_t*)L"FSR2_InputDepth");

	dispatchParameters.motionVectors = ffxGetResourceDX12(fsr2context, resources_copies.MotionVectors, (wchar_t*)L"FSR2_InputMotionVectors");

	if (AutoExposure == false)
		dispatchParameters.exposure = ffxGetResourceDX12(fsr2context, resources_copies.ExposureTexture, (wchar_t*)L"FSR2_InputExposure");

	dispatchParameters.output = ffxGetResourceDX12(fsr2context, resources_copies.Output, (wchar_t*)L"FSR2_OutputUpscaledColor", FFX_RESOURCE_STATE_UNORDERED_ACCESS);

	dispatchParameters.jitterOffset.x = parameter->JitterOffsetX;
	dispatchParameters.jitterOffset.y = parameter->JitterOffsetY;

	dispatchParameters.motionVectorScale.x = parameter->MVScaleX;
	dispatchParameters.motionVectorScale.y = parameter->MVScaleY;

	dispatchParameters.reset = parameter->ResetRender;

	dispatchParameters.enableSharpening = EnableSharpening;
	dispatchParameters.sharpness = Sharpness;

	dispatchParameters.frameTimeDelta = FrameTimeDelta;
	dispatchParameters.preExposure = PreExposure;
	dispatchParameters.renderSize.width = parameter->renderSize.Width;
	dispatchParameters.renderSize.height = parameter->renderSize.Height;

	dispatchParameters.cameraFovAngleVertical = DirectX::XMConvertToRadians(CyberFSRContext->ViewMatrix->GetFov());

	FfxErrorCode errorCode = ffxFsr2ContextDispatch(fsr2context, &dispatchParameters);

}

void D3DCyberFSRRenderTask::end() {
	// copy back and release
}

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
	FeatureContext* deviceContext = CyberFsrContext::instance()->Contexts[InFeatureHandle->Id].get();



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

		D3DCyberFSRRenderTask cyberTask;

		cyberTask.device = device;
		cyberTask.commandList = InCmdList;
		cyberTask.CyberFSRContext = deviceContext;

		cyberTask.setup();

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