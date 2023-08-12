#include "pch.h"

#ifndef CyInt_NVCOMMON
#define CyInt_NVCOMMON

#include "NGX_PFN_Definitions.h"

#define CyberInterposer_DO_DX11
#define CyberInterposer_DO_DX12
//#define CyberInterposer_DO_CUDA
#define CyberInterposer_DO_VULKAN

#define WaitForLoading() if(CyberInterposer::CyberFSRLoaded == false) { std::unique_lock<std::mutex> lock(CyberInterposer::startupMutex); CyberInterposer::InterposerReady_cv.wait(lock, [] { return CyberInterposer::CyberFSRLoaded; }); }

namespace CyberInterposer
{
    struct PFN_Table_T {
        enum class Loading_State {
            Loading_State_Fresh,
            Loading_State_Partial,
            Loading_State_Full,
            Loading_State_Fail
        };

        Loading_State loading_state = Loading_State::Loading_State_Fresh;

        static HMODULE GetHModule(LPCWSTR inputFileName);

        virtual bool LoadDLL(LPCWSTR inputFileName, bool populateChildren);

        virtual bool LoadDLL(HMODULE inputFile, bool populateChildren) = 0;
    };

    typedef size_t File_Details;
}
#endif