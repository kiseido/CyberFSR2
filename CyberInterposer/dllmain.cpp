// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "Interposer.h"
#include "Logger.h"


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CyberFSR::Logger::init();
        CyberLOGy("DLL_PROCESS_ATTACH");
        if (!LoadDependentDLL())
        {
            CyberLOGy("Loading NVNGX.dll failed");
            // Handle the error if the dependent DLL cannot be loaded
            return FALSE;
        }
        break;
    case DLL_THREAD_ATTACH:
        CyberLOGy("DLL_THREAD_ATTACH");
        break;
    case DLL_THREAD_DETACH:
        CyberLOGy("DLL_THREAD_DETACH");
        break;
    case DLL_PROCESS_DETACH:
        CyberLOGy("DLL_PROCESS_DETACH");
        CyberFSR::Logger::cleanup();
        break;
    }
    return TRUE;
}

