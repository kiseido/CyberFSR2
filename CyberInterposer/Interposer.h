#include "pch.h"
#include "PFN_Definitions.h"

#ifndef INTERPOSER
#define INTERPOSER

namespace CyberInterposer
{
    struct PFN_Table_T {
        // Function that loads the dependent DLL and retrieves function pointers
        static HMODULE GetHModule(LPCWSTR inputFileName);
        // Function that loads the dependent DLL and retrieves function pointers
        virtual bool LoadDependentDLL(HMODULE inputFile) = 0;
    };

    struct PFN_Table_DX11 : public  PFN_Table_T {
        PFN_NVSDK_NGX_Parameter_GetD3d11Resource pfn_GetD3d11Resource = nullptr;
        PFN_NVSDK_NGX_Parameter_SetD3d11Resource pfn_SetD3d11Resource = nullptr;

        PFN_NVSDK_NGX_D3D11_Init pfn_D3D11_Init = nullptr;
        PFN_NVSDK_NGX_D3D11_Init_Ext pfn_D3D11_Init_Ext = nullptr;
        PFN_NVSDK_NGX_D3D11_Init_ProjectID pfn_D3D11_Init_ProjectID = nullptr;

        PFN_NVSDK_NGX_D3D11_Shutdown pfn_D3D11_Shutdown = nullptr;
        PFN_NVSDK_NGX_D3D11_Shutdown1 pfn_D3D11_Shutdown1 = nullptr;

        PFN_NVSDK_NGX_D3D11_GetCapabilityParameters pfn_D3D11_GetCapabilityParameters = nullptr;
        PFN_NVSDK_NGX_D3D11_GetParameters pfn_D3D11_GetParameters = nullptr;

        PFN_NVSDK_NGX_D3D11_GetScratchBufferSize pfn_D3D11_GetScratchBufferSize = nullptr;

        PFN_NVSDK_NGX_D3D11_CreateFeature pfn_D3D11_CreateFeature = nullptr;
        PFN_NVSDK_NGX_D3D11_ReleaseFeature pfn_D3D11_ReleaseFeature = nullptr;
        PFN_NVSDK_NGX_D3D11_EvaluateFeature pfn_D3D11_EvaluateFeature = nullptr;
        PFN_NVSDK_NGX_D3D11_EvaluateFeature_C pfn_D3D11_EvaluateFeature_C = nullptr;

        PFN_NVSDK_NGX_D3D11_AllocateParameters pfn_D3D11_AllocateParameters = nullptr;
        PFN_NVSDK_NGX_D3D11_DestroyParameters pfn_D3D11_DestroyParameters = nullptr;

        // Function that loads the dependent DLL and retrieves function pointers
       bool LoadDependentDLL(HMODULE input) override;
    }; 
    
    struct PFN_Table_DX12 : public  PFN_Table_T {
        PFN_NVSDK_NGX_Parameter_SetD3d12Resource pfn_SetD3d12Resource = nullptr;
        PFN_NVSDK_NGX_Parameter_GetD3d12Resource pfn_GetD3d12Resource = nullptr;

        PFN_NVSDK_NGX_D3D12_Init pfn_D3D12_Init = nullptr;
        PFN_NVSDK_NGX_D3D12_Init_Ext pfn_D3D12_Init_Ext = nullptr;
        PFN_NVSDK_NGX_D3D12_Init_ProjectID pfn_D3D12_Init_ProjectID = nullptr;

        PFN_NVSDK_NGX_D3D12_Shutdown pfn_D3D12_Shutdown = nullptr;
        PFN_NVSDK_NGX_D3D12_Shutdown1 pfn_D3D12_Shutdown1 = nullptr;

        PFN_NVSDK_NGX_D3D12_GetCapabilityParameters pfn_D3D12_GetCapabilityParameters = nullptr;
        PFN_NVSDK_NGX_D3D12_GetParameters pfn_D3D12_GetParameters = nullptr;

        PFN_NVSDK_NGX_D3D12_GetScratchBufferSize pfn_D3D12_GetScratchBufferSize = nullptr;

        PFN_NVSDK_NGX_D3D12_AllocateParameters pfn_D3D12_AllocateParameters = nullptr;
        PFN_NVSDK_NGX_D3D12_DestroyParameters pfn_D3D12_DestroyParameters = nullptr;


        PFN_NVSDK_NGX_D3D12_CreateFeature pfn_D3D12_CreateFeature = nullptr;
        PFN_NVSDK_NGX_D3D12_ReleaseFeature pfn_D3D12_ReleaseFeature = nullptr;
        PFN_NVSDK_NGX_D3D12_EvaluateFeature pfn_D3D12_EvaluateFeature = nullptr;
        PFN_NVSDK_NGX_D3D12_EvaluateFeature_C pfn_D3D12_EvaluateFeature_C = nullptr;

        PFN_NVSDK_NGX_D3D12_GetFeatureRequirements pfn_D3D12_GetFeatureRequirements = nullptr;

        // Function that loads the dependent DLL and retrieves function pointers
        bool LoadDependentDLL(HMODULE inputFileName) override;
    };

    struct PFN_Table_Vulkan : public  PFN_Table_T
    {
        PFN_NVSDK_NGX_VULKAN_Init pfn_VULKAN_Init = nullptr;
        PFN_NVSDK_NGX_VULKAN_Init_Ext pfn_VULKAN_Init_Ext = nullptr;
        PFN_NVSDK_NGX_VULKAN_Init_ProjectID pfn_VULKAN_Init_ProjectID = nullptr;

        PFN_NVSDK_NGX_VULKAN_Shutdown pfn_VULKAN_Shutdown = nullptr;
        PFN_NVSDK_NGX_VULKAN_Shutdown1 pfn_VULKAN_Shutdown1 = nullptr;

        PFN_NVSDK_NGX_VULKAN_GetCapabilityParameters pfn_VULKAN_GetCapabilityParameters = nullptr;
        PFN_NVSDK_NGX_VULKAN_GetParameters pfn_VULKAN_GetParameters = nullptr;

        PFN_NVSDK_NGX_VULKAN_AllocateParameters pfn_VULKAN_AllocateParameters = nullptr;
        PFN_NVSDK_NGX_VULKAN_DestroyParameters pfn_VULKAN_DestroyParameters = nullptr;

        PFN_NVSDK_NGX_VULKAN_GetScratchBufferSize pfn_VULKAN_GetScratchBufferSize = nullptr;

        PFN_NVSDK_NGX_VULKAN_CreateFeature pfn_VULKAN_CreateFeature = nullptr;
        PFN_NVSDK_NGX_VULKAN_ReleaseFeature pfn_VULKAN_ReleaseFeature = nullptr;
        PFN_NVSDK_NGX_VULKAN_EvaluateFeature pfn_VULKAN_EvaluateFeature = nullptr;
        PFN_NVSDK_NGX_VULKAN_EvaluateFeature_C pfn_VULKAN_EvaluateFeature_C = nullptr;

        // Function that loads the dependent DLL and retrieves function pointers
        bool LoadDependentDLL(HMODULE inputFileName) override;
    };

    struct PFN_Table_CUDA : public  PFN_Table_T
    {
        PFN_NVSDK_NGX_CUDA_Init pfn_cuInit = nullptr;
        PFN_NVSDK_NGX_CUDA_Init_Ext pfn_cuInit_Ext = nullptr;
        PFN_NVSDK_NGX_CUDA_Init_with_ProjectID pfn_cuInit_with_ProjectID = nullptr;

        PFN_NVSDK_NGX_CUDA_Shutdown pfn_cuShutdown = nullptr;

        PFN_NVSDK_NGX_CUDA_GetCapabilityParameters pfn_cuGetCapabilityParameters = nullptr;

        PFN_NVSDK_NGX_CUDA_AllocateParameters pfn_cuAllocateParameters = nullptr;
        PFN_NVSDK_NGX_CUDA_DestroyParameters pfn_cuDestroyParameters = nullptr;

        PFN_NVSDK_NGX_CUDA_GetScratchBufferSize pfn_cuGetScratchBufferSize = nullptr;

        PFN_NVSDK_NGX_CUDA_CreateFeature pfn_cuCreateFeature = nullptr;
        PFN_NVSDK_NGX_CUDA_ReleaseFeature pfn_cuReleaseFeature = nullptr;
        PFN_NVSDK_NGX_CUDA_EvaluateFeature pfn_cuEvaluateFeature = nullptr;
        PFN_NVSDK_NGX_CUDA_EvaluateFeature_C pfn_cuEvaluateFeature_C = nullptr;

        // Function that loads the dependent DLL and retrieves function pointers
        bool LoadDependentDLL(HMODULE inputFileName) override;
    };

    struct Top_Interposer : public  PFN_Table_T {
        PFN_NVSDK_NGX_UpdateFeature pfn_UpdateFeature = nullptr;

        PFN_NVSDK_NGX_Parameter_SetULL pfn_SetULL = nullptr;
        PFN_NVSDK_NGX_Parameter_GetULL pfn_GetULL = nullptr;

        PFN_NVSDK_NGX_Parameter_SetD pfn_SetD = nullptr;
        PFN_NVSDK_NGX_Parameter_GetD pfn_GetD = nullptr;

        PFN_NVSDK_NGX_Parameter_SetI pfn_SetI = nullptr;
        PFN_NVSDK_NGX_Parameter_GetI pfn_GetI = nullptr;


        PFN_NVSDK_NGX_Parameter_SetF pfn_SetF = nullptr;
        PFN_NVSDK_NGX_Parameter_GetF pfn_GetF = nullptr;

        PFN_NVSDK_NGX_Parameter_SetUI pfn_SetUI = nullptr;
        PFN_NVSDK_NGX_Parameter_GetUI pfn_GetUI = nullptr;

        PFN_NVSDK_NGX_Parameter_SetVoidPointer pfn_SetVoidPointer = nullptr;
        PFN_NVSDK_NGX_Parameter_GetVoidPointer pfn_GetVoidPointer = nullptr;

        PFN_Table_DX11 PFN_DX11;
        PFN_Table_DX12 PFN_DX12;
        PFN_Table_Vulkan PFN_Vulkan;
        PFN_Table_CUDA PFN_CUDA;

        // Function that loads the dependent DLL and retrieves function pointers
        bool LoadDependentDLL(LPCWSTR inputFileName, bool populateChildren);

        bool LoadDependentDLL(HMODULE hModule, bool populateChildren);

        // Function that loads the dependent DLL and retrieves function pointers
        bool LoadDependentDLL(HMODULE input) override;
    };





    static Top_Interposer function_table;

    
};

#endif
