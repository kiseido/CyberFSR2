#pragma once

namespace CyberFSR
{
	// add sub-module names between the defined numbers for easy incrementing and sub-division
	// or just use the code directly but make sure to add a unique number under 65536 to it!
	enum ModuleCode
	{
		Undefined = -1,
		Unset = 0,
		File_Config = 1 << 16,
		File_CyberFsr = 1 << 17,
		File_CyberFsrDx11 = 1 << 18,
		File_CyberFsrDx12 = 1 << 19,
		File_CyberFsrVk = 1 << 20,
		File_DebugOverlay = 1 << 21,
		File_DirectXHooks = 1 << 22,
		File_NvParameter = 1 << 23,
		File_Util = 1 << 24,
		File_ViewMatrixHook = 1 << 25
	};

	constexpr ModuleCode GetPrimaryId(ModuleCode);

	struct EventContainer {
		ModuleCode Module;

	};

	class DebugOverlay
	{
	public:
		DebugOverlay(ID3D12Device* device, ID3D12GraphicsCommandList* cmdList);
		DebugOverlay(VkDevice InDevice, VkCommandBuffer InCmdList);
		~DebugOverlay();
		void Render(ID3D12GraphicsCommandList* cmdList);
		void Render(VkCommandBuffer cmdList);
	};
}