#pragma once
#include "pch.h"
#include "NvParameter.h"

#include <variant>

namespace CyberFSR 
{
	//pre-define some headers
	enum ModuleCode
	{
		Lowest = 0b1 << 31,
		Undefined = -1,
		Unset = 0,
		Sys_Util = 0b1 << 15,
		Sys_Util_Unknown,
		Sys_Config = 0b1 << 16,
		Sys_Config_Unknown,
		Sys_CyberFsr = 0b1 << 17,
		Sys_CyberFsr_Unknown,
		Sys_DebugOverlay = 0b1 << 18,
		Sys_DebugOverlay_Unknown,
		Sys_DirectXHooks = 0b1 << 19,
		Sys_DirectXHooks_Unknown,
		Sys_ViewMatrixHook = 0b1 << 20,
		Sys_ViewMatrixHook_Unknown,
		Sys_NvParameter = 0b1 << 21,
		Sys_NvParameter_Unknown,
		Sys_CyberStorage = 0b1 << 22,
		Sys_CyberStorage_Unknown,
		// can go up to 0b1 << 30 with this pattern
		Highest = 0xffffffff & ~(0b1 << 31),

	};
	struct Log_Small {
		ModuleCode Module;
		unsigned int Time;
	};

	struct Log_Large {
		ModuleCode Module;
		unsigned long long Time;
	};

	struct Log_Buffer {
	private:
		static constexpr unsigned int ValueArrSize = 0b1 << 12;
		unsigned int head = 0;
		unsigned int tail = 0;
		Log_Small values[ValueArrSize];
	public:
		Log_Small get();
		bool put();
	};
	//class CyberStorage;

	constexpr ModuleCode GetPrimaryId(ModuleCode);

	class CyberStorage
	{
	private:
		typedef std::variant<
			void*,
			std::unique_ptr<void>,
			// D3D
			std::shared_ptr<ID3D11Resource>,
			std::shared_ptr<ID3D12Resource>,
			// VK
			std::shared_ptr<NVSDK_NGX_Resource_VK>,
			std::shared_ptr<NVSDK_NGX_ImageViewInfo_VK>,
			std::shared_ptr<NVSDK_NGX_BufferInfo_VK>,
			std::shared_ptr<NVSDK_NGX_Resource_VK>,
			// DLSS
			std::shared_ptr<NVSDK_NGX_Feature>,
			std::shared_ptr<NVSDK_NGX_Parameter>
		> Cyber_Resource_Pointer;

		template <typename type = Cyber_Resource_Pointer>
		using Cyber_Garage = std::map<void*, std::shared_ptr<type>>;
		static Cyber_Garage<CyberStorage> SuperStorage;

		// DLSS related stuff
		static Cyber_Garage<NvParameter> NvParameters;
		static Cyber_Garage<NVSDK_NGX_Feature_Create_Params> Feature_Create_Params;
		static Cyber_Garage<NVSDK_NGX_DLSS_Create_Params> DLSS_Create_Params;
		static Cyber_Garage<NVSDK_NGX_DLDenoise_Create_Params> DLDenoise_Create_Params;

		// D3D related stuff
		static Cyber_Garage<ID3D11Resource> ID3D11Resources;
		static Cyber_Garage<ID3D12Resource> ID3D12Resources;

		// Vulkan related stuff


		// FSR related stuff

	public:
		static Log_Buffer Interal_Logs;
	};

	// add sub-module names between the defined numbers for automated incrementing and sub-division
}
