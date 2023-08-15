#include "pch.h"
#include "CFSR_Logging.h"

#include "DebugOverlay.h"

#ifdef CyberFSR_DO_OVERLAY2
#include <windows.h>
#include <string>
#include <chrono>
#include <thread>
#include <iomanip>

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

void DisplayTimeOnWindow() {
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = L"TimeDisplayWindow";

    if (!RegisterClass(&wc)) {
        return;
    }

    HWND hwnd = CreateWindowEx(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        L"TimeDisplayWindow",
        L"TimeDisplayWindow",
        WS_POPUPWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 200, 30,
        NULL, NULL, GetModuleHandle(NULL), NULL
    );

    if (!hwnd) {
        return;
    }

    while (true) {
        HWND foregroundWindow = GetForegroundWindow();
        if (foregroundWindow) {
            RECT rect;
            GetWindowRect(foregroundWindow, &rect);
            SetWindowPos(hwnd, NULL, rect.left + 10, rect.top + 10, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

            std::time_t t = std::time(nullptr);
            std::tm tm;
            localtime_s(&tm, &t);
            std::wostringstream wos;
            wos << std::put_time(&tm, L"%Y-%m-%d %H:%M:%S");
            std::wstring timeStr = wos.str();

            HDC hdc = GetDC(hwnd);
            TextOut(hdc, 10, 10, timeStr.c_str(), static_cast<int>(timeStr.size()));
            ReleaseDC(hwnd, hdc);

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}
#endif

#ifdef CyberFSR_DO_OVERLAY

const wchar_t DebugOverlay::TextLayer::TextType[] = L"Text";
const wchar_t DebugOverlay::LayerTreeNode::TreeNodeType[] = L"TreeNode";


void DebugOverlay::LayerTreeNode::AddChild(int id, std::shared_ptr<Layer> layer) {
    CyberLogArgs();
    children[id] = layer;
}

bool DebugOverlay::LayerTreeNode::RemoveChild(int id) {
    CyberLogArgs();
    auto it = children.find(id);
    if (it != children.end()) {
        children.erase(it);
        return true;
    }
    return false;
}

std::shared_ptr<DebugOverlay::Layer> DebugOverlay::LayerTreeNode::GetChild(int id) {
    CyberLogArgs();
    auto it = children.find(id);
    if (it != children.end()) {
        return it->second;
    }
    return nullptr;
}

HWND GetActiveWindowHandle() {
    return GetForegroundWindow();
}

DebugOverlay::DebugOverlay() : targetWindow(GetActiveWindowHandle()), d2dFactory(nullptr), dwFactory(nullptr), d2dRenderTarget(nullptr), textFormat(nullptr) {
    CyberLogArgs();
    if (!InitializeResources()) {
        // Handle initialization failure
        // Possibly log an error message or throw an exception
        return;
    }
}

DebugOverlay::~DebugOverlay() {
    CyberLogArgs();
    ReleaseResources();
}

void DebugOverlay::Render() {
    CyberLogArgs();

    if (!d2dRenderTarget) {
        return;
    }

    d2dRenderTarget->BeginDraw();

    // Rendering the timestamp
    SYSTEMTIME currentTime;
    GetLocalTime(&currentTime);
    std::wstring timestampText = L"Timestamp: " + std::to_wstring(currentTime.wHour) + L":" +
        std::to_wstring(currentTime.wMinute) + L":" + std::to_wstring(currentTime.wSecond);

    D2D1_RECT_F layoutRect = D2D1::RectF(0.0f, 0.0f, 300.0f, 100.0f);
    d2dRenderTarget->DrawTextW(
        timestampText.c_str(), timestampText.size(), textFormat, layoutRect, nullptr, D2D1_DRAW_TEXT_OPTIONS_NONE, DWRITE_MEASURING_MODE_NATURAL
    );

    d2dRenderTarget->EndDraw();
}

bool DebugOverlay::InitializeResources() {
    CyberLogArgs();

    HRESULT hr = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &d2dFactory);
    if (FAILED(hr)) {
        return false;
    }

    hr = DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory), reinterpret_cast<IUnknown**>(&dwFactory));
    if (FAILED(hr)) {
        return false;
    }

    hr = d2dFactory->CreateHwndRenderTarget(
        D2D1::RenderTargetProperties(),
        D2D1::HwndRenderTargetProperties(targetWindow, D2D1::SizeU(0, 0)),
        &d2dRenderTarget
    );
    if (FAILED(hr)) {
        return false;
    }

    hr = dwFactory->CreateTextFormat(L"Arial", nullptr, DWRITE_FONT_WEIGHT_NORMAL, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 16.0f, L"", &textFormat);
    if (FAILED(hr)) {
        return false;
    }

    return true;
}

void DebugOverlay::ReleaseResources() {
    CyberLogArgs();

    if (textFormat) {
        textFormat->Release();
        textFormat = nullptr; // Reset the pointer to null after release
    }
    if (dwFactory) {
        dwFactory->Release();
        dwFactory = nullptr;
    }
    if (d2dRenderTarget) {
        d2dRenderTarget->Release();
        d2dRenderTarget = nullptr;
    }
    if (d2dFactory) {
        d2dFactory->Release();
        d2dFactory = nullptr;
    }
}

#endif