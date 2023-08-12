#include "pch.h"
#include "NGX_Interposer.h"
#include "CI_Logging.h"

HMODULE dllModule;

const LPCWSTR cyberFSRdllFileName = L"CyberFSR.dll";


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
       

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        {
            if (!CyberInterposer::CyberFSRLoaded)
            {
                {
                    std::lock_guard<std::mutex> lock(CyberInterposer::startupMutex);

                    if (!CyberInterposer::LoggerLoaded)
                    {
                        CyberInterposer::logger.start();
                        CyberInterposer::LoggerLoaded = true;
                        //CyberInterposer::logger.config(LogFilename, true, true, true);
                        //CyberLOGi("CyberLOGi test");
                        //CyberLOGw("CyberLOGw test");
                        //CyberLOGe("CyberLOGe test");
                        //CyberLogLots("CyberLogLots test", "");
                        //CyberLogArgs("CyberLogArgs test", "");
                    }

                    const auto hmodule = LoadLibraryW(cyberFSRdllFileName);

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
                    CyberInterposer::CyberFSRLoaded = true;
                }
                CyberInterposer::InterposerReady_cv.notify_all();
            }
        }
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
