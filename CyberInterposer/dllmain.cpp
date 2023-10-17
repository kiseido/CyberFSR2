#include "pch.h"
#include "NGX_Interposer.h"
#include "CI_Logging.h"

#define IMGUI_DEFINE_MATH_OPERATORS
#include "imgui_internal.h"
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include <d3d11.h>
#pragma comment(lib, "d3d11.lib")

#include <chrono>
#include <ctime>


#include <unordered_map>
#include <mutex>
#include <random>

HMODULE dllModule;

template <typename T>
struct vec2 { T x; T y; };

using vec2f = vec2<float>;
using vec2i = vec2<int>;

class OverlayState {
public:
    OverlayState();

    void InitBouncingBehavior();
    void UpdateOverlayPosition(float deltaTime);
    void RenderOverlay();
    bool InitDirectX11(HWND hwnd);
    void CleanupDirectX11();
    void InitImGui(HWND hwnd);
    void CleanupImGui();
    void DrawImGui();

    void SetupHooks(HMODULE hModule);
    void CleanupHooks();

    bool overlayVisible;
    bool inputCaptured;

private:

    HHOOK hKeyboardHook = NULL;
    HHOOK hMouseHook = NULL;

    vec2f bounce;
    vec2f speed;
    vec2i screen;

    const float BOUNCE_SPEED = 2.0f;
    const float OVERLAY_WIDTH = 200.0f;
    const float OVERLAY_HEIGHT = 50.0f;

    ID3D11Device* pd3dDevice;
    ID3D11DeviceContext* pd3dDeviceContext;
    IDXGISwapChain* pSwapChain;
    ID3D11RenderTargetView* mainRenderTargetView;
};

class OverlayManager {
public:
    static OverlayManager& GetInstance();
    OverlayState* getOverlayForProcess(DWORD processId);
    void removeOverlayForProcess(DWORD processId);

private:
    OverlayManager() = default;
    ~OverlayManager() = default;
    OverlayManager(const OverlayManager&) = delete;
    OverlayManager& operator=(const OverlayManager&) = delete;

    std::unordered_map<DWORD, OverlayState> processOverlays;
    mutable std::mutex overlayMutex;
};

void OverlayState::CleanupHooks() {
    if (hKeyboardHook) UnhookWindowsHookEx(hKeyboardHook);
    if (hMouseHook) UnhookWindowsHookEx(hMouseHook);
}

bool OverlayState::InitDirectX11(HWND hwnd) {
    // Setup the DirectX 11 context and devices
    DXGI_SWAP_CHAIN_DESC scd = {};
    scd.BufferCount = 1;
    scd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    scd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    scd.OutputWindow = hwnd;
    scd.SampleDesc.Count = 1;
    scd.Windowed = TRUE;

    HRESULT result = D3D11CreateDeviceAndSwapChain(
        NULL,
        D3D_DRIVER_TYPE_HARDWARE,
        NULL,
        0,
        NULL,
        0,
        D3D11_SDK_VERSION,
        &scd,
        &pSwapChain,
        &pd3dDevice,
        NULL,
        &pd3dDeviceContext);

    if (FAILED(result)) {
        return false;
    }

    ID3D11Texture2D* pBackBuffer;
    pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)&pBackBuffer);
    pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &mainRenderTargetView);
    pBackBuffer->Release();

    pd3dDeviceContext->OMSetRenderTargets(1, &mainRenderTargetView, NULL);

    return true;
}

void OverlayState::CleanupDirectX11() {
    if (mainRenderTargetView) mainRenderTargetView->Release();
    if (pSwapChain) pSwapChain->Release();
    if (pd3dDeviceContext) pd3dDeviceContext->Release();
    if (pd3dDevice) pd3dDevice->Release();
}

void OverlayState::InitImGui(HWND hwnd) {
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    ImGui::StyleColorsDark();

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(pd3dDevice, pd3dDeviceContext);
}

void OverlayState::CleanupImGui() {
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
}

void OverlayState::DrawImGui() {
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    // Your ImGui rendering code
    RenderOverlay();

    ImGui::Render();
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
}


OverlayState::OverlayState()
    : overlayVisible(true), inputCaptured(false), bounce({ 0.0f, 0.0f }), speed({ 0.0f, 0.0f }),
    screen({ 0, 0 }), pd3dDevice(nullptr), pd3dDeviceContext(nullptr), pSwapChain(nullptr),
    mainRenderTargetView(nullptr) {}

void OverlayState::InitBouncingBehavior() {
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_real_distribution<float> dist(-1.0, 1.0);
    speed.x = dist(mt);
    speed.y = dist(mt);

    RECT desktop;
    const HWND hDesktop = GetDesktopWindow();
    GetWindowRect(hDesktop, &desktop);
    screen.x = desktop.right;
    screen.y = desktop.bottom;
}

void OverlayState::UpdateOverlayPosition(float deltaTime) {
    bounce.x += speed.x * BOUNCE_SPEED * deltaTime;
    bounce.y += speed.y * BOUNCE_SPEED * deltaTime;

    if (bounce.x < 0.0f || bounce.x + OVERLAY_WIDTH > screen.x) speed.x = -speed.x;
    if (bounce.y < 0.0f || bounce.y + OVERLAY_HEIGHT > screen.y) speed.y = -speed.y;
}

void OverlayState::RenderOverlay() {
    if (!overlayVisible) return;

    ImGui::SetNextWindowPos(ImVec2(bounce.x, bounce.y));
    ImGui::SetNextWindowSize(ImVec2(OVERLAY_WIDTH, OVERLAY_HEIGHT));
    ImGui::Begin("Overlay", NULL, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove);

    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    char buf[100];
    struct tm timeinfo;
    if (localtime_s(&timeinfo, &time) == 0) {
        strftime(buf, sizeof(buf), "%H:%M:%S", &timeinfo);
        ImGui::Text("Current Time: %s", buf);
    }
    else {
        ImGui::Text("Error: Unable to get local time");
    }

    ImGui::End();
}


OverlayManager& OverlayManager::GetInstance() {
    static OverlayManager instance;
    return instance;
}

OverlayState* OverlayManager::getOverlayForProcess(DWORD processId) {
    std::lock_guard<std::mutex> guard(overlayMutex);
    if (processOverlays.find(processId) == processOverlays.end()) {
        processOverlays.emplace(processId, OverlayState());
    }
    return &processOverlays[processId];
}

void OverlayManager::removeOverlayForProcess(DWORD processId) {
    std::lock_guard<std::mutex> guard(overlayMutex);
    processOverlays.erase(processId);
}

bool IsOverlaySequenceDown() {
    return (GetAsyncKeyState(VK_BACK) & 0x8000) &&
        (GetAsyncKeyState(VK_CONTROL) & 0x8000) &&
        (GetAsyncKeyState(VK_MENU) & 0x8000);
}

LRESULT CALLBACK KeyboardProcHook(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT* pKeyStruct = (KBDLLHOOKSTRUCT*)lParam;
        if (pKeyStruct && pKeyStruct->vkCode == VK_BACK && IsOverlaySequenceDown()) {
            auto* overlay = OverlayManager::GetInstance().getOverlayForProcess(GetCurrentProcessId());
            overlay->overlayVisible = !overlay->overlayVisible;
            overlay->inputCaptured = !overlay->inputCaptured;
        }
    }
    auto* overlay = OverlayManager::GetInstance().getOverlayForProcess(GetCurrentProcessId());
    if (overlay && overlay->inputCaptured) return 1;

    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

LRESULT CALLBACK MouseProcHook(int nCode, WPARAM wParam, LPARAM lParam) {
    auto* overlay = OverlayManager::GetInstance().getOverlayForProcess(GetCurrentProcessId());
    if (overlay && overlay->inputCaptured) return 1;
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

void OverlayState::SetupHooks(HMODULE hModule) {
    hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProcHook, hModule, 0);
    hMouseHook = SetWindowsHookEx(WH_MOUSE_LL, MouseProcHook, hModule, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);
        dllModule = hModule;

        auto* overlay = OverlayManager::GetInstance().getOverlayForProcess(GetCurrentProcessId());
        HWND hwnd = GetActiveWindow();
        if (!overlay->InitDirectX11(hwnd)) return FALSE;

        overlay->InitImGui(hwnd);
        overlay->InitBouncingBehavior();

        overlay->SetupHooks(hModule);
        break;
    }

    case DLL_PROCESS_DETACH:
    {
        auto procid = GetCurrentProcessId();
        auto& overlayManager = OverlayManager::GetInstance();
        auto* overlay = overlayManager.getOverlayForProcess(procid);
        overlay->CleanupHooks();  // Call the new UnsetHook function
        overlayManager.removeOverlayForProcess(procid);
        break;
    }
    }

    return TRUE;
}
