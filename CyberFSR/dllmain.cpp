#include "pch.h"
#include "CFSR_logging.h"

HMODULE dllModule;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    CyberFSR::logger.start(L"CyberFSR.log", true, true, true);
    

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CyberLOGy("CyberFSR_DLL_PROCESS_ATTACH");
        DisableThreadLibraryCalls(hModule);
        dllModule = hModule;
        break;
    case DLL_THREAD_ATTACH:
        CyberLOGy("CyberFSR_DLL_THREAD_ATTACH");
        break;
    case DLL_THREAD_DETACH:
        CyberLOGy("CyberFSR_DLL_THREAD_DETACH");
        break;
    case DLL_PROCESS_DETACH:
        CyberLOGy("CyberFSR_DLL_PROCESS_DETACH");
        CyberFSR::logger.stop();
        break;
    }
    return TRUE;
}

