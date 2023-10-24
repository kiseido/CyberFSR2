#include "pch.h"
#include "NGX_Interposer.h"
#include "CI_Logging.h"

#include "InterposerWindow.h"
#include "InterposerOverlay.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    CyberInterposer::interposer.init();

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        CyberLOGvi("Interposer_DLL_PROCESS_ATTACH");
        DisableThreadLibraryCalls(hModule);
        InterposerWindow::GetInstance().Start(hModule);
        //ProcessID pid = GetCurrentProcessId(); // needs some sort of casting
        //ConnectionManager::GetInstance().getConnectionForProcess(pid)->Initialize();
        break;
    }
    case DLL_PROCESS_DETACH: {
        CyberLOGvi("Interposer_DLL_PROCESS_DETACH");
        //ProcessID pid = GetCurrentProcessId();// needs some sort of casting
        //ConnectionManager::GetInstance().endConnectionForProcess(pid);
        CyberInterposer::logger.stop();
        break;
    }
    case DLL_THREAD_ATTACH:
        CyberLOGvi("Interposer_DLL_THREAD_ATTACH");
        break;
    case DLL_THREAD_DETACH:
        CyberLOGvi("Interposer_DLL_THREAD_DETACH");
        break;
    }

    return TRUE;
}



