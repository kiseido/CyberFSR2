#include "pch.h"
#include "CFSR_Logging.h"

#include "DebugOverlay.h"


#ifdef CyberFSR_DO_OVERLAY3
#include <windows.h>
#include <string>
#include <chrono>
#include <thread>
#include <iomanip>
#include <dxgi1_4.h>
#include <wrl/client.h>


std::wstring GetTimeString() {
    std::time_t t = std::time(nullptr);
    std::tm tm;
    localtime_s(&tm, &t);
    std::wostringstream wos;
    wos << std::put_time(&tm, L"%Y-%m-%d %H:%M:%S");
    return wos.str();
}

namespace CyberFSROverlay {
    bool Overlay::setupWindow() {
        if (!parentWindow) {
            parentWindow = GetActiveWindow();

            if (parentWindow) {
                windowClass.lpfnWndProc = WndProc;
                windowClass.hInstance = GetModuleHandle(NULL);
                windowClass.lpszClassName = L"TimeDisplayWindow";

                if (!RegisterClass(&windowClass)) {
                    CyberLOGe("RegisterClass failed");
                    return false;
                }

                ourWindow = CreateWindowEx(
                    WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
                    L"TimeDisplayWindow",
                    L"TimeDisplayWindow",
                    WS_POPUPWINDOW | WS_VISIBLE,
                    CW_USEDEFAULT, CW_USEDEFAULT, 200, 30,
                    NULL, NULL, GetModuleHandle(NULL), this
                );

                if (!ourWindow) {
                    CyberLOGe("CreateWindowEx failed");
                    return false;
                }

                return true;
            }
            else {
                CyberLOGe("getting parent window failed");
            }
        }
        else {
            CyberLOGvi("parentWindow already set");
        }
        return false;
    }



    Overlay::Overlay() {
    };

    bool Overlay::Draw() {
        if (ourWindow && parentWindow) {
            RECT parentDimensions;
            GetWindowRect(parentWindow, &parentDimensions);
            SetWindowPos(ourWindow, NULL, parentDimensions.left + 10, parentDimensions.top + 10, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

            std::wstring timeStr = GetTimeString();

            HDC hdc = GetDC(ourWindow);
            TextOut(hdc, 10, 10, timeStr.c_str(), static_cast<int>(timeStr.size()));
            ReleaseDC(ourWindow, hdc);

            return true;
        }
    }

    LRESULT Overlay::NonStaticWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
        switch (message) {
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        case WM_NCHITTEST:
            return HTTRANSPARENT;
        case WM_NCPAINT:
            Draw();
            break;
        default:
            return DefWindowProcW(hWnd, message, wParam, lParam);
        }
        return 0;
    }

    LRESULT CALLBACK Overlay::WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
        Overlay* pThis;

        switch (message) {
        case WM_NCCREATE: {
            pThis = static_cast<Overlay*>(reinterpret_cast<CREATESTRUCT*>(lParam)->lpCreateParams);
            SetWindowLongPtr(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
        }
            break;
        default:
            pThis = reinterpret_cast<Overlay*>(GetWindowLongPtr(hWnd, GWLP_USERDATA));
            if (pThis) {
                return pThis->NonStaticWndProc(hWnd, message, wParam, lParam);
            }
            else {
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        return 0;
    }

    bool CyberFSROverlay::Overlay::setupWindowDX(ID3D12GraphicsCommandList* InCmdList) {
        using Microsoft::WRL::ComPtr;

        if (parentWindow != NULL) {
            CyberLOGvi("parentWindow already set in setupWindowDX");
            return false; // It's already set up.
        }

        // Obtain the device first.
        ID3D12Device* device;
        InCmdList->GetDevice(IID_PPV_ARGS(&device));

        // Assuming you have access to the swap chain somehow.
        ComPtr<IDXGISwapChain3> swapChain;
        // Retrieve your swap chain here.

        if (!swapChain) {
            CyberLOGe("swapChain is null in setupWindowDX");
            return false; // Failed to obtain swap chain.
        }

        HWND tempParentWindow = nullptr;
        HRESULT hr = swapChain->GetHwnd(&tempParentWindow);

        if (SUCCEEDED(hr) && tempParentWindow) {
            parentWindow = tempParentWindow;
            return setupWindow();
        }
        else {
            CyberLOGe("Failed to get HWND from swap chain in setupWindowDX");
            return false; // Failed to obtain HWND.
        }
    }

}




#endif

#ifdef CyberFSR_DO_OVERLAY2
#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dwrite.lib")

#include <d3d11.h>
#include <d2d1.h>
#include <dwrite.h>
#include <windows.h>
#include <string>
#include <chrono>
#include <thread>
#include <iomanip>
#include <random>

namespace CyberFSROverlay {
    HANDLE overlay = nullptr;

    void CreateDirectWriteFactoryAndTextFormat(IDWriteFactory** dwFactory, IDWriteTextFormat** textFormat) {
        HRESULT hr = DWriteCreateFactory(
            DWRITE_FACTORY_TYPE_SHARED,
            __uuidof(IDWriteFactory),
            reinterpret_cast<IUnknown**>(dwFactory)
        );
        if (FAILED(hr)) {
            CyberLOGe("DWriteCreateFactory failed");
            return;
        }
        hr = (*dwFactory)->CreateTextFormat(
            L"Arial",
            NULL,
            DWRITE_FONT_WEIGHT_NORMAL,
            DWRITE_FONT_STYLE_NORMAL,
            DWRITE_FONT_STRETCH_NORMAL,
            20.0f,
            L"en-US",
            textFormat
        );
        if (FAILED(hr)) {
            CyberLOGe("CreateTextFormat failed");
            return;
        }
    }

    LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
        switch (message) {
        case WM_NCHITTEST:
            return HTTRANSPARENT;
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        case WM_CREATE:
        case WM_NULL:
        case WM_MOVE:
        case WM_SIZE:
        case WM_ACTIVATE:
        case WM_SYSCOMMAND:
        case WM_TIMER:
        case WM_HSCROLL:
        case WM_VSCROLL:
        case WM_INITMENU:
        case WM_INITMENUPOPUP:
        case WM_MENUSELECT:
        case WM_MENUCHAR:
        case WM_ENTERIDLE:
        case WM_MENUCOMMAND:
        case WM_NCCALCSIZE:
        case WM_CAPTURECHANGED:
        case WM_CONTEXTMENU:
        case WM_NCMOUSEMOVE:
        case WM_NCLBUTTONDOWN:
        case WM_NCLBUTTONUP:
        case WM_NCLBUTTONDBLCLK:
        case WM_NCRBUTTONDOWN:
        case WM_NCRBUTTONUP:
        case WM_NCRBUTTONDBLCLK:
        case WM_NCMBUTTONDOWN:
        case WM_NCMBUTTONUP:
        case WM_NCMBUTTONDBLCLK:
        case WM_MOUSEMOVE:
        case WM_NCPAINT:
        case WM_KEYDOWN:
        case WM_KEYUP:
        case WM_UNICHAR:
        case WM_INPUT:
        case WM_INPUTLANGCHANGEREQUEST:
        case WM_INPUTLANGCHANGE:
        case WM_IME_STARTCOMPOSITION:
        case WM_IME_ENDCOMPOSITION:
        case 7:
        case 20:
        case 24:
        case 28:
        case 70:
        case 71:
        case 129:
        case 130:
        case 134:
        case 641:
        case 642:
            return DefWindowProcW(hWnd, message, wParam, lParam);
        default:
            CyberLOGe("Unknown WndProc message received", message, wParam, lParam);
            return DefWindowProcW(hWnd, message, wParam, lParam);
        }
        return 0;
    }

    inline bool MoveTextBox(const HWND& hwnd, int& x, int& y, int& dx, int& dy, const int& width, const int& height) {
        RECT clientRect;
        bool ts = GetClientRect(hwnd, &clientRect);

        if (!ts) {
            CyberLOGe("GetClientRect failed");
            return false;
        }

        x += dx;
        y += dy;

        if (x < 0 || x + width > clientRect.right) {
            dx = -dx;
        }
        if (y < 0 || y + height > clientRect.bottom) {
            dy = -dy;
        }

        return SetWindowPos(hwnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    }

    void DisplayTimeOnWindow() {
        int x = 10, y = 10;
        int dx = 5, dy = 5;
        int width = 200, height = 30;

        std::random_device rd;
        std::mt19937 rng(rd());
        std::uniform_int_distribution<int> dist(-5, 5);

        // Initialize Direct3D
        D3D_FEATURE_LEVEL featureLevel;
        ID3D11Device* device = nullptr;
        ID3D11DeviceContext* context = nullptr;
        IDXGISwapChain* swapChain = nullptr;

        HWND hwnd = nullptr;

        HWND foregroundWindow = nullptr;

        DXGI_SWAP_CHAIN_DESC scDesc = {};

        HRESULT hr = 0;

        WNDCLASS wc = { 0 };


        try {
            wc.lpfnWndProc = WndProc;
            wc.hInstance = GetModuleHandle(NULL);
            wc.lpszClassName = L"TimeDisplayWindow";

            if (!RegisterClass(&wc)) {
                CyberLOGe("RegisterClass failed");
                return;
            }

            hwnd = CreateWindowEx(
                WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
                L"TimeDisplayWindow",
                L"TimeDisplayWindow",
                WS_POPUPWINDOW | WS_VISIBLE,
                CW_USEDEFAULT, CW_USEDEFAULT, 200, 30,
                NULL, NULL, GetModuleHandle(NULL), NULL
            );

            if (!hwnd) {
                CyberLOGe("CreateWindowEx failed");
                return;
            }
        
            scDesc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
            scDesc.SampleDesc.Count = 1;
            scDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
            scDesc.BufferCount = 1;
            scDesc.OutputWindow = hwnd;
            scDesc.Windowed = TRUE;

            UINT createDeviceFlags = 0;
#ifdef _DEBUG
            createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
#endif

            hr = D3D11CreateDeviceAndSwapChain(
                nullptr,
                D3D_DRIVER_TYPE_HARDWARE,
                nullptr,
                createDeviceFlags,
                nullptr,
                0,
                D3D11_SDK_VERSION,
                &scDesc,
                &swapChain,
                &device,
                &featureLevel,
                &context
            );

            if (FAILED(hr)) {
                CyberLOGe("D3D11CreateDeviceAndSwapChain failed");

                ID3D11InfoQueue* debug_info_queue;
                device->QueryInterface(__uuidof(ID3D11InfoQueue), (void**)&debug_info_queue);

                UINT64 message_count = debug_info_queue->GetNumStoredMessages();

                for (UINT64 i = 0; i < message_count; i++) {
                    SIZE_T message_size = 0;
                    debug_info_queue->GetMessage(i, nullptr, &message_size); //get the size of the message

                    D3D11_MESSAGE* message = (D3D11_MESSAGE*)malloc(message_size); //allocate enough space
                    debug_info_queue->GetMessageW(i, message, &message_size);

                    CyberTypes::CyString formattedMessage = std::format("Directx11: %.*s", std::string_view(message->pDescription, message->DescriptionByteLength));

                    CyberLOGe(formattedMessage);

                    free(message);
                }

                debug_info_queue->ClearStoredMessages();

                return;
            }

            foregroundWindow = GetForegroundWindow();

            if (foregroundWindow) {

                ID2D1Factory* d2dFactory = nullptr;
                D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &d2dFactory);
                ID2D1RenderTarget* rt = nullptr;
                ID2D1SolidColorBrush* brush = nullptr;
                IDWriteFactory* dwFactory = nullptr;
                IDWriteTextFormat* textFormat = nullptr;
                CreateDirectWriteFactoryAndTextFormat(&dwFactory, &textFormat);

                // Get the DXGI Surface from the Swap Chain
                IDXGISurface* pDxgiBackBuffer = nullptr;

                MSG msg = {};

                std::wostringstream wos;

                hr = swapChain->GetBuffer(0, __uuidof(IDXGISurface), reinterpret_cast<void**>(&pDxgiBackBuffer));

                if (FAILED(hr)) {
                    CyberLOGe("swapChain->GetBuffer failed");
                    return;
                }

                D2D1_RENDER_TARGET_PROPERTIES props = D2D1::RenderTargetProperties(
                    D2D1_RENDER_TARGET_TYPE_DEFAULT,
                    D2D1::PixelFormat(DXGI_FORMAT_UNKNOWN, D2D1_ALPHA_MODE_PREMULTIPLIED)
                );

                hr = d2dFactory->CreateDxgiSurfaceRenderTarget(pDxgiBackBuffer, props, &rt);

                if (FAILED(hr)) {
                    CyberLOGe("CreateDxgiSurfaceRenderTarget failed");
                    return;
                }

                while (SUCCEEDED(hr) && msg.message != WM_QUIT) {

                    if (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
                        TranslateMessage(&msg);
                        DispatchMessage(&msg);
                    }

                    MoveTextBox(hwnd, x, y, dx, dy, width, height);

                    std::time_t t = std::time(nullptr);
                    std::tm tm;
                    localtime_s(&tm, &t);
                    wos << std::put_time(&tm, L"%Y-%m-%d %H:%M:%S");
                    std::wstring timeStr = wos.str();
                    wos.clear();


                    rt->BeginDraw();
                    rt->SetTransform(D2D1::Matrix3x2F::Identity());
                    rt->Clear(D2D1::ColorF(0.0f, 0.0f, 0.0f, 0.0f)); // Transparent
                    rt->CreateSolidColorBrush(D2D1::ColorF(D2D1::ColorF::White), &brush);
                    rt->DrawTextW(timeStr.c_str(), timeStr.length(), textFormat, D2D1::RectF(0, 0, 200, 30), brush);
                    hr = rt->EndDraw();

                    if (FAILED(hr)) {
                        CyberLOGe("EndDraw failed");
                        return;
                    }

                    auto ret = rt->Release();

                    // Present the back buffer to the screen
                    hr = swapChain->Present(1, 0);

                    if (FAILED(hr)) {
                        CyberLOGe("swapChain->Present failed");
                        return;
                    }

                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }

                pDxgiBackBuffer->Release();
                pDxgiBackBuffer = nullptr;
                // Clean up Direct3D resources
                brush->Release();
                textFormat->Release();
                dwFactory->Release();
                d2dFactory->Release();
            }
        }
        catch (const std::exception& e) {
            CyberLOGe("Exception occurred: ", e.what());
        }
        catch (...) {
            CyberLOGe("Unknown exception occurred");
        }
    }
}


#endif

#ifdef CyberFSR_DO_OVERLAY1

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")

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
        CyberLogArgs("InitializeResources failed");
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
        CyberLOGe("d2dRenderTarget is null");
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

    try {
        HRESULT hr = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &d2dFactory);
        if (FAILED(hr)) {
            CyberLOGe("D2D1CreateFactory D2D1_FACTORY_TYPE_SINGLE_THREADED failed");
            return false;
        }

        hr = DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory), reinterpret_cast<IUnknown**>(&dwFactory));
        if (FAILED(hr)) {
            CyberLOGe("DWriteCreateFactory DWRITE_FACTORY_TYPE_SHARED failed");
            return false;
        }

        hr = d2dFactory->CreateHwndRenderTarget(
            D2D1::RenderTargetProperties(),
            D2D1::HwndRenderTargetProperties(targetWindow, D2D1::SizeU(0, 0)),
            &d2dRenderTarget
        );
        if (FAILED(hr)) {
            CyberLOGe(" d2dFactory->CreateHwndRenderTarget failed");
            return false;
        }

        hr = dwFactory->CreateTextFormat(L"Arial", nullptr, DWRITE_FONT_WEIGHT_NORMAL, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 16.0f, L"", &textFormat);
        if (FAILED(hr)) {
            CyberLOGe("dwFactory->CreateTextFormat failed");
            return false;
        }
    }
    catch (const std::exception& e) {
        CyberLOGe("Exception occurred: ", e.what());
        return false;
    }
    catch (...) {
        CyberLOGe("Unknown exception occurred");
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