#include "pch.h"
#include "DebugOverlay.h"

namespace CyberFSR
{
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