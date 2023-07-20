#include "pch.h"
#include "NGX_Interposer.h"
#include "CI_Logging.h"

HMODULE dllModule;

static const LPCWSTR cyberFSRdllFileName = L"CyberFSR.dll";

static bool CyberFSRLoaded = false;
static bool LoggerLoaded = false;
static std::mutex startupMutex;


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    {
        std::lock_guard<std::mutex> lock(startupMutex);

        if (!LoggerLoaded)
        {
            LoggerLoaded = true;
            CyberInterposer::logger.start(L"CyberInterposer.log", true, true, true);
            CyberLOGy("CyberLOGy test");
            CyberLogLots("CyberLogLots test", "");
            CyberLogArgs("CyberLogArgs test", "");
        }

        if (!CyberFSRLoaded)
        {
            CyberFSRLoaded = true;

            const bool dllLoadStatus = CyberInterposer::DLLs.LoadDLL(LoadLibraryW(cyberFSRdllFileName), true);

            if (!dllLoadStatus)
            {
                CyberLOGy("Loading NVNGX.dll failed");
                // Handle the error if the dependent DLL cannot be loaded
                // return FALSE;
            }
        }
    }

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        CyberLOGy("Interposer_DLL_PROCESS_ATTACH");
        DisableThreadLibraryCalls(hModule);
        dllModule = hModule;
        break;
    }
    case DLL_THREAD_ATTACH:
        CyberLOGy("Interposer_DLL_THREAD_ATTACH");
        break;
    case DLL_THREAD_DETACH:
        CyberLOGy("Interposer_DLL_THREAD_DETACH");
        break;
    case DLL_PROCESS_DETACH:
        CyberLOGy("Interposer_DLL_PROCESS_DETACH");
        CyberInterposer::logger.stop();
        break;
    }

    return TRUE;
}
