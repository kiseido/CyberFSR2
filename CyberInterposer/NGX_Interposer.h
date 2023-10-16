#include "pch.h"

#ifndef CyInt_INTERPOSER
#define CyInt_INTERPOSER

#include "CI_Logging.h"
#include "CyberNGX.h"

#include "Common.h"
#include "Config.h"

#include "NGX_Cuda.h"
#include "NGX_DX11.h"
#include "NGX_DX12.h"
#include "NGX_Vk.h"
#include "NGX_Parameter.h"

constexpr wchar_t const*  cyberinterposerdllFileName = L"CyberInterposer.ini";

NVSDK_NGX_Result C_Declare NVSDK_NGX_GetVersion(NVSDK_NGX_Version* version);

namespace CyberInterposer
{

    template <typename T>
    bool LoadFunction(T& functionPointer, HMODULE hModule, const char* functionName)
    {
        functionPointer = reinterpret_cast<T>(GetProcAddress(hModule, functionName));
        if (functionPointer != nullptr)
        {
            CyberLOGi(functionName, " found", functionPointer);
            return true;
        }
        else
        {
            CyberLOGi(functionName, " not found");
            return false;
        }
    }

    struct PFN_Table_NVNGX_Top_Interposer : public  PFN_Table_T {

        PFN_NVSDK_NGX_UpdateFeature pfn_UpdateFeature = nullptr;
#ifdef CyberInterposer_DO_DX11
        PFN_Table_NVNGX_DX11 PFN_DX11;
#endif
#ifdef CyberInterposer_DO_DX12
        PFN_Table_NVNGX_DX12 PFN_DX12;
#endif
#ifdef CyberInterposer_DO_VULKAN
        PFN_Table_NVNGX_Vulkan PFN_Vulkan;
#endif
#ifdef CyberInterposer_DO_CUDA
        PFN_Table_NVNGX_CUDA PFN_CUDA;
#endif

        bool LoadDLL(HMODULE inputFile, bool populateChildren) override;
    };

    struct NVNGX_NvDLL : PFN_Table_T {
        HMODULE hmodule = 0;

        time_t load_time = 0;

        File_Details file_details = 0;

        std::string file_name;
        std::string file_path;

        PFN_Table_NVNGX_Top_Interposer pointer_tables;

        bool LoadDLL(HMODULE inputFile, bool populateChildren) override;
    };

    struct DLLRepo : PFN_Table_T {
    public:
        static constexpr size_t RepoMaxLoadedDLLs = 128;
    private:
        struct Connection {
            HMODULE hmodule;
            size_t dll_index_to_use;
            time_t connected_since;
        };

        struct ProcessConnection : Connection {
            DWORD process_id;
        };
        struct ThreadConnection : Connection {
            std::thread::id thread_id;
        };

        std::unordered_map<HMODULE,ProcessConnection> connected_processes;
        std::unordered_map<HMODULE,ThreadConnection> connected_threads;

        std::array<NVNGX_NvDLL, RepoMaxLoadedDLLs> dlls;
        size_t index_in_use = -1;
        size_t next_index = -1;

        std::mutex indexlock;

    public:
        bool LoadDLL(HMODULE hModule, bool populateChildren) override;

        bool UseLoadedDLL(size_t index);
        const std::array<NVNGX_NvDLL, RepoMaxLoadedDLLs>* GetLoadedDLLs();
        const NVNGX_NvDLL& GetLoadedDLL();

        void ThreadConnect(HMODULE hModule);
        void ThreadDisconnect(HMODULE hModule);

        void ProcessConnect(HMODULE hModule);
        void ProcessDisconnect(HMODULE hModule);
    };

    struct Interposer {
        std::atomic<bool> InterposerInitialized = false;
        std::atomic<bool> LoggerLoaded = false;
        std::mutex startupMutex;
        std::condition_variable InterposerReady_cv;

        Interposer();
        void wait_for_ready();
        bool is_ready();

        int init();
    };

    extern DLLRepo DLLs;

    extern Interposer interposer;
};

#endif
