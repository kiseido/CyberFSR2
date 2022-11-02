#pragma once
#include "pch.h"
#include "NvParameter.h"

#include <typeindex>
#include <typeinfo>
#include <variant>

#include <iostream>
#include <map>
#include <string>
#include <typeinfo>

namespace CyberFSR 
{
	class CyberStorage
	{
	public:
		using Cyber_Resource_Pointer = std::variant<
			void*,
			std::shared_ptr<ID3D11Resource>,
			std::shared_ptr<ID3D12Resource>,
			std::shared_ptr<NVSDK_NGX_Resource_VK>,
			std::shared_ptr<NVSDK_NGX_ImageViewInfo_VK>,
			std::shared_ptr<NVSDK_NGX_BufferInfo_VK>,
			std::shared_ptr<NVSDK_NGX_Resource_VK>,
			std::shared_ptr<NVSDK_NGX_Feature>,
			std::shared_ptr<NVSDK_NGX_Parameter>
		>;

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

		template <typename type>
		using Cyber_Garage = std::map<void*, std::shared_ptr<type>>;

	private:
		// DLSS related stuff
		static Cyber_Garage<NvParameter> Allocated_Parameters;
		static Cyber_Garage<NVSDK_NGX_Feature_Create_Params> Allocated_Feature_Create_Params;
		static Cyber_Garage<NVSDK_NGX_DLSS_Create_Params> Allocated_DLSS_Create_Params;
		static Cyber_Garage<NVSDK_NGX_DLDenoise_Create_Params> Allocated_DLDenoise_Create_Params;

		// D3D related stuff
		static Cyber_Garage<ID3D11Resource> Allocated_ID3D11Resource;
		static Cyber_Garage<ID3D12Resource> Allocated_ID3D12Resource;

		// Vulkan related stuff


		// FSR related stuff

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

