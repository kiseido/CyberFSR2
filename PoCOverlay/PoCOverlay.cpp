// PoCOverlay.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "PoCOverlay.h"


// This is an example of an exported variable
POCOVERLAY_API int nPoCOverlay=0;

// This is an example of an exported function.
POCOVERLAY_API int fnPoCOverlay(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
CPoCOverlay::CPoCOverlay()
{
    return;
}


#include <imgui_impl_dx12.h>
#include <imgui_impl_win32.h>
#include <thread>
#include <chrono>

Overlay::Overlay(HWND hWnd) : m_hWnd(hWnd), m_positionX(100), m_positionY(100), m_velocityX(2.0f), m_velocityY(2.0f) {
    Initialize();
}

void Overlay::Initialize() {
    // Initialize D3D12 device
    D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&m_device));

    // Initialize ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui_ImplWin32_Init(m_hWnd);
    ImGui_ImplDX12_Init(m_device.Get(), 3, DXGI_FORMAT_R8G8B8A8_UNORM, m_srvHeap.Get(),
        m_srvHeap->GetCPUDescriptorHandleForHeapStart(),
        m_srvHeap->GetGPUDescriptorHandleForHeapStart());
}

RECT Overlay::GetWindowDimensions() {
    RECT rect;
    GetClientRect(m_hWnd, &rect);
    return rect;
}

void Overlay::Render() {
    auto [windowWidth, windowHeight] = GetWindowDimensions();
    m_positionX += m_velocityX;
    m_positionY += m_velocityY;

    if (m_positionX < 0 || m_positionX > windowWidth) {
        m_velocityX = -m_velocityX;
    }

    if (m_positionY < 0 || m_positionY > windowHeight) {
        m_velocityY = -m_velocityY;
    }

    ImGui_ImplDX12_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    ImGui::SetCursorPos(ImVec2(m_positionX, m_positionY));
    ImGui::TextUnformatted("overlay");

    ImGui::Render();
    ImGui_ImplDX12_RenderDrawData(ImGui::GetDrawData(), nullptr);  // Update this based on your D3D12 command list setup
}

extern "C" __declspec(dllexport) void ShowOverlay() {
    static Overlay overlay(GetConsoleWindow());  // Replace with your application's HWND

    std::this_thread::sleep_for(std::chrono::seconds(5));

    while (true) {
        overlay.Render();
        std::this_thread::sleep_for(std::chrono::milliseconds(16)); // Sleep to control FPS
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        std::thread(ShowOverlay).detach();
        break;
    case DLL_PROCESS_DETACH:
        // Add cleanup here if necessary
        break;
    }
    return TRUE;
}
