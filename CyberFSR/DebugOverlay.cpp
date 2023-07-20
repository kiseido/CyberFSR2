#include "pch.h"
#include "DebugOverlay.h"
#include "CFSR_Logging.h"

DebugOverlay::DebugOverlay(ID3D12Device* device, ID3D12GraphicsCommandList* cmdList)
{
	CyberLOG();
}

DebugOverlay::DebugOverlay(VkDevice InDevice, VkCommandBuffer InCmdList)
{
	CyberLOG();
}

DebugOverlay::~DebugOverlay()
{
	CyberLOG();
}

void DebugOverlay::Render(ID3D12GraphicsCommandList* cmdList)
{
	CyberLOG();
}

void DebugOverlay::Render(VkCommandBuffer cmdList)
{
	CyberLOG();
}
