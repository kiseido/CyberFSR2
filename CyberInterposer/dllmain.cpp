#include "pch.h"
#include "NGX_Interposer.h"
#include "CI_Logging.h"

HMODULE dllModule;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    CyberInterposer::interposer.init();

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {

        CyberLOGvi("Interposer_DLL_PROCESS_ATTACH");
        DisableThreadLibraryCalls(hModule);
        dllModule = hModule;
        break;
    }
    case DLL_THREAD_ATTACH:
        CyberLOGvi("Interposer_DLL_THREAD_ATTACH");
        break;
    case DLL_THREAD_DETACH:
        CyberLOGvi("Interposer_DLL_THREAD_DETACH");
        break;
    case DLL_PROCESS_DETACH:
        CyberLOGvi("Interposer_DLL_PROCESS_DETACH");
        CyberInterposer::logger.stop();
        break;
    }

    return TRUE;
}
