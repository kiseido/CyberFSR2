// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "Interposer.h"
#include "Logging.h"


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
 
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        CyberInterposer::logger.start(L"CyberInterposer.log", true, true, true);

        CyberLOGy("DLL_PROCESS_ATTACH");

        const bool dllLoadStatus = CyberInterposer::function_table.LoadDependentDLL(L"nvngx.dll", true);

        if (!dllLoadStatus)
        {
            CyberLOGy("Loading NVNGX.dll failed");
            // Handle the error if the dependent DLL cannot be loaded
            //return FALSE;
        }
        break;
    }
    case DLL_THREAD_ATTACH:
        CyberLOGy("DLL_THREAD_ATTACH");
        break;
    case DLL_THREAD_DETACH:
        CyberLOGy("DLL_THREAD_DETACH");
        break;
    case DLL_PROCESS_DETACH:
        CyberLOGy("DLL_PROCESS_DETACH");
        CyberInterposer::logger.stop();
        break;
    }
    return TRUE;
}

