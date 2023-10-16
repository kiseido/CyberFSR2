#include "pch.h"
#include "NGX_Interposer.h"

namespace CyberInterposer {
    DLLRepo DLLs = DLLRepo();

    Interposer interposer = Interposer();

    Interposer::Interposer() {

    }

    int Interposer::init() {
        if (InterposerInitialized == true) return 0;

        std::lock_guard<std::mutex> lock(startupMutex);
        
        if (InterposerInitialized == true) return 0;

        InterposerConfig.loadFromFile(cyberinterposerdllFileName);
        InterposerConfig.saveToFile(cyberinterposerdllFileName);

        if (LoggerLoaded == false)
        {
            logger.start();
            LoggerLoaded = true;
            //CyberInterposer::logger.config(LogFilename, true, true, true);
            //CyberLOGi("CyberLOGi test");
            //CyberLOGw("CyberLOGw test");
            //CyberLOGe("CyberLOGe test");
            //CyberLogLots("CyberLogLots test", "");
            //CyberLogArgs("CyberLogArgs test", "");
        }


        const auto dllFileName = std::get<std::wstring>(InterposerConfig[L"DLSSBackEnd"][L"DLL"].value);

        CyberLOGi("Loading ", dllFileName);

        const auto hmodule = LoadLibraryW(dllFileName.c_str());

        if (!hmodule)
        {
            CyberLOGe("Loading NVNGX.dll failed");
            // Handle the error if the dependent DLL cannot be loaded
            // return FALSE;
        }
        else {
            const bool dllLoadStatus = CyberInterposer::DLLs.LoadDLL(hmodule, true);

            if (!dllLoadStatus)
            {
                CyberLOGe("LoadDLL failed");
                // Handle the error if the dependent DLL cannot be loaded
                // return FALSE;
            }
        }
        InterposerInitialized = true;
    
        InterposerReady_cv.notify_all();
        
        return 1;
    }

    void Interposer::wait_for_ready() {
        if (InterposerInitialized) return;

        std::unique_lock<std::mutex> lock(startupMutex);
        InterposerReady_cv.wait(lock, [this] { return InterposerInitialized == true; });
    }

    bool Interposer::is_ready() {
        return InterposerInitialized;
    }


    bool PFN_Table_NVNGX_Top_Interposer::LoadDLL(HMODULE hModule, bool populateChildren)
    {
        CyberLogArgs(hModule, populateChildren);

        if (hModule == nullptr) {
            CyberLOGe("hModule is bad");
            return false;
        }

        bool foundFunctions = true;

        if (populateChildren) {
#ifdef CyberInterposer_DO_DX11
            const bool foundDx11 = PFN_DX11.LoadDLL(hModule, false);

            foundFunctions &= foundDx11;

            if (foundDx11)
            {
                CyberLOGi("DX11 functions loaded");
            }
            else
            {
                CyberLOGe("DX11 functions not found");
            }
#endif
#ifdef CyberInterposer_DO_DX12
            const bool foundDx12 = PFN_DX12.LoadDLL(hModule, false);

            foundFunctions &= foundDx12;

            if (foundDx12)
            {
                CyberLOGi("DX12 functions loaded");
            }
            else
            {
                CyberLOGe("DX12 functions not found");
            }
#endif
#ifdef CyberInterposer_DO_CUDA
            const bool foundCuda = PFN_CUDA.LoadDLL(hModule, false);

            foundFunctions &= foundCuda;

            if (foundCuda)
            {
                CyberLOGi("CUDA functions loaded");
            }
            else
            {
                CyberLOGe("CUDA functions not found");
            }
#endif
#ifdef CyberInterposer_DO_VULKAN
            const bool foundVulkan = PFN_Vulkan.LoadDLL(hModule, false);

            foundFunctions &= foundVulkan;

            if (foundVulkan)
            {
                CyberLOGi("Vulkan functions loaded");
            }
            else
            {
                CyberLOGe("Vulkan functions not found");
            }
#endif

            return foundFunctions;
        }
        return false;

    }

    inline HMODULE PFN_Table_T::GetHModule(LPCWSTR inputFileName)
    {
        CyberLogArgs(inputFileName);

        HMODULE hModule = LoadLibraryW(inputFileName);

        return hModule;
    }

    bool DLLRepo::LoadDLL(HMODULE hModule, bool populateChildren)
    {
        CyberLogArgs(hModule, populateChildren);

        if (index_in_use == -1) index_in_use = 0;

        return dlls[index_in_use].LoadDLL(hModule, populateChildren);
    }

    bool DLLRepo::UseLoadedDLL(size_t index)
    {
        CyberLogArgs(index);
        return false;
    }

    const std::array<NVNGX_NvDLL, DLLRepo::RepoMaxLoadedDLLs>* DLLRepo::GetLoadedDLLs()
    {
        CyberLOG();

        return &dlls;
    }

    const NVNGX_NvDLL& DLLRepo::GetLoadedDLL()
    {
        CyberLOG();

        return dlls[0];
    }

    void DLLRepo::ThreadConnect(HMODULE hModule)
    {
        CyberLogArgs(hModule);
    }

    void DLLRepo::ThreadDisconnect(HMODULE hModule)
    {
        CyberLogArgs(hModule);
    }

    void DLLRepo::ProcessConnect(HMODULE hModule)
    {
        CyberLogArgs(hModule);
    }

    void DLLRepo::ProcessDisconnect(HMODULE hModule)
    {
        CyberLogArgs(hModule);
    }

    bool NVNGX_NvDLL::LoadDLL(HMODULE inputFile, bool populateChildren)
    {
        return pointer_tables.LoadDLL(inputFile, populateChildren);
    }
}

NVSDK_NGX_Result C_Declare NVSDK_NGX_GetVersion(NVSDK_NGX_Version* version)
{
    CyberLogArgs(version);

    return NVSDK_NGX_Result_Fail;
}

NVSDK_NGX_Result C_Declare NVSDK_NGX_UpdateFeature(const NVSDK_NGX_Application_Identifier* ApplicationId, const NVSDK_NGX_Feature FeatureID)
{
    CyberLogArgs(ApplicationId, FeatureID);

    return NVSDK_NGX_Result_Fail;
}