#include "pch.h"
#include "CFSR_logging.h"

const LPCWSTR CFSR_LogFilename = L"CyberFSR.log";

HMODULE dllModule;

bool LoggerLoaded = false;
std::mutex startupMutex;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    //CyberFSR::logger.config(LogFilename, true, true, true);
    //CyberFSR::logger.start(LogFilename, true, true, true);
    //CyberFSR::logger.start(LogFilename, true, true, true);

    std::lock_guard<std::mutex> lock(startupMutex);

    if (!LoggerLoaded)
    {
        LoggerLoaded = true;
        //CyberInterposer::logger.config(LogFilename, true, true, true);
        CyberFSR::logger.start();
        CyberLOG();
        CyberLOGvi(L"CyberLOGvi test");
        CyberLOGi(L"CyberLOGi test");
        CyberLOGw(L"CyberLOGw test");
        CyberLOGe(L"CyberLOGe test");
        CyberLogLots(L"CyberLogLots test", L"");
        CyberLogArgs(L"CyberLogArgs test", L"");
    }
    
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CyberLOGvi(L"CyberFSR_DLL_PROCESS_ATTACH");
        DisableThreadLibraryCalls(hModule);
        dllModule = hModule;
        break;
    case DLL_THREAD_ATTACH:
        CyberLOGvi(L"CyberFSR_DLL_THREAD_ATTACH");
        break;
    case DLL_THREAD_DETACH:
        CyberLOGvi(L"CyberFSR_DLL_THREAD_DETACH");
        break;
    case DLL_PROCESS_DETACH:
        CyberLOGvi(L"CyberFSR_DLL_PROCESS_DETACH");
        CyberFSR::logger.stop();
        break;
    }
    return TRUE;
}

