#include "pch.h"
#include "Interposer.h"
#include "Logger.h"

using namespace Interposer;

// Function that loads the dependent DLL and retrieves function pointers
bool Interposer::LoadDependentDLL(LPCWSTR inputFileName)
{
    CyberLOGy(CyberLogger::convertLPCWSTRToString(inputFileName));
    HMODULE hModule = LoadLibraryW(inputFileName);
    if (hModule != nullptr)
    {
        // common
        pfn_SetULL = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetULL>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_SetULL"));
        pfn_SetF = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetF>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_SetF"));
        pfn_SetD = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetD>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_SetD"));
        pfn_SetUI = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetUI>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_SetUI"));
        pfn_SetI = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetI>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_SetI"));
        pfn_SetD3d11Resource = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetD3d11Resource>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_SetD3d11Resource"));
        pfn_SetD3d12Resource = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetD3d12Resource>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_SetD3d12Resource"));
        pfn_SetVoidPointer = reinterpret_cast<PFN_NVSDK_NGX_Parameter_SetVoidPointer>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_SetVoidPointer"));
        pfn_GetULL = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetULL>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_GetULL"));
        pfn_GetF = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetF>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_GetF"));
        pfn_GetD = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetD>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_GetD"));
        pfn_GetUI = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetUI>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_GetUI"));
        pfn_GetI = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetI>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_GetI"));
        pfn_GetI = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetI>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_GetI"));
        pfn_GetD3d11Resource = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetD3d11Resource>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_GetD3d11Resource"));
        pfn_GetD3d12Resource = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetD3d12Resource>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_GetD3d12Resource"));
        pfn_GetVoidPointer = reinterpret_cast<PFN_NVSDK_NGX_Parameter_GetVoidPointer>(GetProcAddress(hModule, "NVSDK_NGX_Parameter_GetVoidPointer"));

        // DX11
		pfn_D3D11_Init = reinterpret_cast<PFN_NVSDK_NGX_D3D11_Init>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_Init"));
		pfn_D3D11_Init_Ext = reinterpret_cast<PFN_NVSDK_NGX_D3D11_Init_Ext>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_Init_Ext"));
		pfn_D3D11_Shutdown = reinterpret_cast<PFN_NVSDK_NGX_D3D11_Shutdown>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_Shutdown"));
		pfn_D3D11_GetParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D11_GetParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_GetParameters"));
		pfn_D3D11_GetScratchBufferSize = reinterpret_cast<PFN_NVSDK_NGX_D3D11_GetScratchBufferSize>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_GetScratchBufferSize"));
		pfn_D3D11_CreateFeature = reinterpret_cast<PFN_NVSDK_NGX_D3D11_CreateFeature>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_CreateFeature"));
		pfn_D3D11_ReleaseFeature = reinterpret_cast<PFN_NVSDK_NGX_D3D11_ReleaseFeature>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_ReleaseFeature"));
		pfn_D3D11_EvaluateFeature = reinterpret_cast<PFN_NVSDK_NGX_D3D11_EvaluateFeature>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_EvaluateFeature"));
		pfn_D3D11_GetCapabilityParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D11_GetCapabilityParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_GetCapabilityParameters"));
		pfn_D3D11_AllocateParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D11_AllocateParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_AllocateParameters"));
		pfn_D3D11_DestroyParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D11_DestroyParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D11_DestroyParameters"));

        // DX12
        pfn_D3D12_Init_Ext = reinterpret_cast<PFN_NVSDK_NGX_D3D12_Init_Ext>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_Init_Ext"));
        pfn_D3D12_Init = reinterpret_cast<PFN_NVSDK_NGX_D3D12_Init>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_Init"));
        pfn_D3D12_Init_ProjectID = reinterpret_cast<PFN_NVSDK_NGX_D3D12_Init_ProjectID>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_Init_ProjectID"));
        pfn_D3D12_Shutdown = reinterpret_cast<PFN_NVSDK_NGX_D3D12_Shutdown>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_Shutdown"));
        pfn_D3D12_Shutdown1 = reinterpret_cast<PFN_NVSDK_NGX_D3D12_Shutdown1>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_Shutdown1"));
        pfn_D3D12_GetParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D12_GetParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_GetParameters"));
        pfn_D3D12_GetCapabilityParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D12_GetCapabilityParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_GetCapabilityParameters"));
        pfn_D3D12_AllocateParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D12_AllocateParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_AllocateParameters"));
        pfn_D3D12_DestroyParameters = reinterpret_cast<PFN_NVSDK_NGX_D3D12_DestroyParameters>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_DestroyParameters"));
        pfn_D3D12_GetScratchBufferSize = reinterpret_cast<PFN_NVSDK_NGX_D3D12_GetScratchBufferSize>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_GetScratchBufferSize"));
        pfn_D3D12_CreateFeature = reinterpret_cast<PFN_NVSDK_NGX_D3D12_CreateFeature>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_CreateFeature"));
        pfn_D3D12_ReleaseFeature = reinterpret_cast<PFN_NVSDK_NGX_D3D12_ReleaseFeature>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_ReleaseFeature"));
        pfn_D3D12_GetFeatureRequirements = reinterpret_cast<PFN_NVSDK_NGX_D3D12_GetFeatureRequirements>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_GetFeatureRequirements"));
        pfn_D3D12_EvaluateFeature = reinterpret_cast<PFN_NVSDK_NGX_D3D12_EvaluateFeature>(GetProcAddress(hModule, "NVSDK_NGX_D3D12_EvaluateFeature"));

        // Vulkan

        return true;
    }

    return false;
}


NVSDK_NGX_API NVSDK_NGX_Result NVSDK_NGX_D3D12_Init_Ext(unsigned long long InApplicationId, const wchar_t* InApplicationDataPath,
	ID3D12Device* InDevice, const NVSDK_NGX_FeatureCommonInfo* InFeatureInfo, NVSDK_NGX_Version InSDKVersion,
	unsigned long long unknown0)
{
	CyberLOG();
#ifdef _DEBUG
	AllocConsole();
	FILE* fDummy;
	freopen_s(&fDummy, "CONIN$", "r", stdin);
	freopen_s(&fDummy, "CONOUT$", "w", stderr);
	freopen_s(&fDummy, "CONOUT$", "w", stdout);
#endif // _DEBUG

	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

NVSDK_NGX_Result NVSDK_NGX_UpdateFeature(const NVSDK_NGX_Application_Identifier* ApplicationId, const NVSDK_NGX_Feature FeatureID)
{
	CyberLOG();
	// is pointer good? cast pointer and call it and return any results!
	return NVSDK_NGX_Result_Success;
}

