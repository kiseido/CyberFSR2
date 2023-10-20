#pragma once

#define IMGUI_DEFINE_MATH_OPERATORS
#include "imgui_internal.h"
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

template <typename T>
struct vec2 { T x; T y; };

using vec2f = vec2<float>;
using vec2i = vec2<int>;

using WindowID = HWND;
using ProcessID = HWND;

class Overlay {
public:
    Overlay(WindowID);
    ~Overlay();

    void Update(WindowID swapWindow = NULL);
    void Render();
    void ToggleVisibility();

    bool IsVisible() const;
    void SetVisible(bool visible);


    static LRESULT CALLBACK KeyboardProcHook(int nCode, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK MouseProcHook(int nCode, WPARAM wParam, LPARAM lParam);

    bool IsOverlaySequenceDown();

private:
    void InitDirectX11();
    void CleanupDirectX11();
    void InitImGui();
    void CleanupImGui();
    void InitBouncingBehavior();
    void UpdateOverlayPosition(float deltaTime);

    std::atomic<bool> overlayActive;

    vec2f bounce;
    vec2f speed;
    vec2i screen;

    static const float BOUNCE_SPEED;
    static const float OVERLAY_WIDTH;
    static const float OVERLAY_HEIGHT;

    ID3D11Device* pd3dDevice;
    ID3D11DeviceContext* pd3dDeviceContext;
    IDXGISwapChain* pSwapChain;
    ID3D11RenderTargetView* mainRenderTargetView;

    WindowID targetWindow;

    HHOOK keyboardHook;
    HHOOK mouseHook;
};


class ProcessConnection {
public:
    ProcessConnection();
    ~ProcessConnection();

    void Initialize();
    void Cleanup();

    std::shared_ptr<Overlay> GetOverlayForWindow(WindowID);

    void StartOverlay(WindowID);
    void StopOverlay(WindowID);

    void SetupHooks();
    void CleanupHooks();

private:
    void ThreadMain();

    struct Process_Attached_Args {
        HMODULE hModule;
        DWORD ul_reason_for_call;
        LPVOID lpReserved;
    } init_args;


    std::unordered_map<WindowID, std::shared_ptr<Overlay>> overlays;
    mutable std::mutex overlaysMutex;

    std::thread overlayThread;
    std::atomic<bool> running = false;

    ProcessID processId;
};

class ConnectionManager {
public:
    static ConnectionManager& GetInstance();
    std::shared_ptr<ProcessConnection> getConnectionForProcess(ProcessID);
    void endConnectionForProcess(ProcessID);

private:
    ConnectionManager() = default;
    ~ConnectionManager() = default;
    ConnectionManager(const ConnectionManager&) = delete;
    ConnectionManager& operator=(const ConnectionManager&) = delete;

    std::unordered_map<ProcessID, std::shared_ptr<ProcessConnection>> processConnections;
    mutable std::mutex connectionMutex;
};