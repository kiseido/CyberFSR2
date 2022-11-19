#pragma once
#include "pch.h"

typedef void(__fastcall* SETCOMPUTEROOTSIGNATURE)(ID3D12GraphicsCommandList* commandList, ID3D12RootSignature* pRootSignature);

extern ID3D12CommandList* myCommandList;

extern std::unordered_map<ID3D12GraphicsCommandList*, std::pair<ID3D12RootSignature*, unsigned long long>> commandListVector;

extern std::mutex rootSigMutex;

void HookSetComputeRootSignature(ID3D12GraphicsCommandList* InCmdList);