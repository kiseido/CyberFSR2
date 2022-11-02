#pragma once
#include "pch.h"
#include "NvParameter.h"

#include <variant>

namespace CyberFSR 
{
	class CyberStorage;

	class CyberStorage
	{
		typedef std::variant<
			void*,
			std::shared_ptr<ID3D11Resource>,
			std::shared_ptr<ID3D12Resource>,
			std::shared_ptr<NVSDK_NGX_Resource_VK>,
			std::shared_ptr<NVSDK_NGX_ImageViewInfo_VK>,
			std::shared_ptr<NVSDK_NGX_BufferInfo_VK>,
			std::shared_ptr<NVSDK_NGX_Resource_VK>,
			std::shared_ptr<NVSDK_NGX_Feature>,
			std::shared_ptr<NVSDK_NGX_Parameter>
		> Cyber_Resource_Pointer;

		template <typename type>
		using Cyber_Garage = std::map<void*, std::shared_ptr<type>>;
	private:
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
		//static ModuleCode Interal_Logs[5000];
		//static NvLogStruct Nv_Logs[5000];

		//	using Cyber_Resource_Pointer = union {
		//		void* Raw;
		//		std::unique_ptr<void> Function;
		//		// D3D
		//		std::unique_ptr<ID3D11Resource> D3D11_Resource;
		//		std::unique_ptr<ID3D12Resource> D3D12_Resource;
		//		// VK
		//		std::unique_ptr<ID3D12Resource> VK_Resource;
		//		std::unique_ptr<NVSDK_NGX_Resource_VK> NGX_Resource_VK;
		//		std::unique_ptr<NVSDK_NGX_ImageViewInfo_VK> NGX_ImageViewInfo_VK;
		//		std::unique_ptr<NVSDK_NGX_BufferInfo_VK> NGX_BufferInfo_VK;
		//		std::unique_ptr<NVSDK_NGX_Resource_VK> NGX_Resource_VK;
		//		// DLSS
		//		std::unique_ptr<NVSDK_NGX_Feature> NGX_Feature;
		//		std::unique_ptr<NVSDK_NGX_Parameter> NGX_Parameter;
		//	};

			//typedef std::pair<std::type_index, Cyber_Resource_P> Cyber_Resource;
	};

	// add sub-module names between the defined numbers for automated incrementing and sub-division
	enum ModuleCode
	{
		Lowest = 0b1 << 31,
		Undefined = -1,
		Unset = 0,
		Sys_Util = 0b1 << 15,

		Sys_Config = 0b1 << 16,

		Sys_CyberFsr = 0b1 << 17,

		Sys_DebugOverlay = 0b1 << 18,

		Sys_DirectXHooks = 0b1 << 19,

		Sys_ViewMatrixHook = 0b1 << 20,

		Sys_NvParameter = 0b1 << 21,

		Sys_CyberStorage = 0b1 << 22,

		// can go up to 0b1 << 30 with this pattern
		Highest = 0xffffffff & ~(0b1<<31),

	};	

	constexpr ModuleCode GetPrimaryId(ModuleCode);

	struct EventContainer {
		ModuleCode Module;

	};
}
