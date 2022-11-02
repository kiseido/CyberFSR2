#include "pch.h"
#include "DebugOverlay.h"

namespace CyberFSR
{
	static ModuleCode Interal_Logs[];

	DebugOverlay::DebugOverlay(ID3D12Device* device, ID3D12GraphicsCommandList* cmdList)
	{
	}

	DebugOverlay::DebugOverlay(VkDevice InDevice, VkCommandBuffer InCmdList)
	{
	}

	DebugOverlay::~DebugOverlay()
	{
	}

	void DebugOverlay::Render(ID3D12GraphicsCommandList* cmdList)
	{
	}

	void DebugOverlay::Render(VkCommandBuffer cmdList)
	{
	}

	constexpr ModuleCode GetPrimaryId(ModuleCode InValue) 
	{
		// magic number int size, 32bit
		constexpr unsigned int MAX_INT = 1 << 31;
		unsigned int i = MAX_INT;
		do 
		{
			i = i >> 1;
		} 
		while ((i & InValue) == 0 || i != 0);

		return (ModuleCode)i;
	}
}

struct NvLogStruct{
	const std::string message; // we really need a fixed size format
	NVSDK_NGX_Logging_Level loggingLevel;
	NVSDK_NGX_Feature sourceComponent;
};

NvLogStruct Nv_Logs[];

// Do not touch Nv_Log_Buffer, it's not thread safe
NvLogStruct Nv_Log_Buffer[];

void NVSDK_NGX_AppLogCallback(const char* message, NVSDK_NGX_Logging_Level loggingLevel, NVSDK_NGX_Feature sourceComponent)
{

}

//              A logging callback provided by the app to allow piping log lines back to the app.
//              Please take careful note of the signature and calling convention.
//              The callback must be able to be called from any thread.
//              It must also be fully thread-safe and any number of threads may call into it concurrently. 
//              It must fully process message by the time it returns, and there is no guarantee that
//              message will still be valid or allocated after it returns.
//              message will be a null-terminated string and may contain multibyte characters.
// 
// 
//        #if defined(__GNUC__) || defined(__clang__)
//        typedef void NVSDK_CONV(*NVSDK_NGX_AppLogCallback)(const char* message, NVSDK_NGX_Logging_Level loggingLevel, NVSDK_NGX_Feature sourceComponent);
//        #else
//        typedef void(NVSDK_CONV* NVSDK_NGX_AppLogCallback)(const char* message, NVSDK_NGX_Logging_Level loggingLevel, NVSDK_NGX_Feature sourceComponent);
//        #endif