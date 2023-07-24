#include "pch.h"

#include "CyberWindow.h"



#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "D3dcompiler.lib")
#pragma comment(lib, "d2d1.lib")

CyberWindow::TextRenderer::TextRenderer(HINSTANCE hInstance) : hInstance_(hInstance), hwnd_() {}

CyberWindow::TextRenderer::~TextRenderer() {
    if (pD2DRenderTarget_ != nullptr)
        pD2DRenderTarget_->Release();
    if (pD2DFactory_ != nullptr)
        pD2DFactory_->Release();
    if (pRenderTargetView_ != nullptr)
        pRenderTargetView_->Release();
    if (pDWriteFactory_ != nullptr)
        pDWriteFactory_->Release();
    if (pTextFormat_ != nullptr)
        pTextFormat_->Release();
    if (pDeviceContext_ != nullptr)
        pDeviceContext_->Release();
    if (pDevice_ != nullptr)
        pDevice_->Release();

    UnregisterClass(L"MyWindowClass", hInstance_);
    DestroyWindow(hwnd_);
}

void CyberWindow::TextRenderer::RenderTextUsingDirect2D(int x, int y, const std::wstring& text) {
    if (!pD2DRenderTarget_ || !pDWriteFactory_ || !pTextFormat_)
        return;

    pD2DRenderTarget_->BeginDraw();
    pD2DRenderTarget_->SetTransform(D2D1::Matrix3x2F::Identity());
    pD2DRenderTarget_->Clear(D2D1::ColorF(D2D1::ColorF::Black, 0.0f));

    //pD2DRenderTarget_->DrawTextW(text.c_str(), static_cast<UINT32>(text.length()), pTextFormat_, D2D1::RectF(static_cast<FLOAT>(x), static_cast<FLOAT>(y), static_cast<FLOAT>(x + 200), static_cast<FLOAT>(y + 100)), nullptr, D2D1::ColorF(D2D1::ColorF::White));

    pD2DRenderTarget_->EndDraw();
}

BOOL CyberWindow::TextRenderer::InitializeAndRender() {
    if (!CreateWindowAndDirectX())
        return FALSE;

    MSG msg;
    ZeroMemory(&msg, sizeof(msg));
    while (msg.message != WM_QUIT) {
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        else {
            // RenderText();
        }
    }

    return TRUE;
}

void CyberWindow::TextRenderer::AddOverlay(const std::wstring& text, int x, int y) {
    overlays_.push_back({ text, x, y });
}

void CyberWindow::TextRenderer::UpdateOverlayPosition(size_t index, int x, int y) {
    if (index < overlays_.size()) {
        overlays_[index].x = x;
        overlays_[index].y = y;
    }
}

void CyberWindow::TextRenderer::RemoveOverlay(size_t index) {
    if (index < overlays_.size()) {
        overlays_.erase(overlays_.begin() + index);
    }
}

BOOL CyberWindow::TextRenderer::CreateWindowAndDirectX() {
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = DefWindowProc;
    wc.hInstance = hInstance_;
    wc.lpszClassName = L"MyWindowClass";
    RegisterClass(&wc);
    hwnd_ = CreateWindow(L"MyWindowClass", L"My Window", WS_OVERLAPPEDWINDOW, 0, 0, 800, 600, NULL, NULL, hInstance_, NULL);

    if (hwnd_ == NULL)
        return FALSE;

    D3D_FEATURE_LEVEL featureLevel;
    HRESULT hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, nullptr, 0, D3D11_SDK_VERSION, &pDevice_, &featureLevel, &pDeviceContext_);
    if (FAILED(hr))
        return FALSE;

    IDXGIFactory* pFactory;
    CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)&pFactory);

    DXGI_SWAP_CHAIN_DESC scDesc;
    ZeroMemory(&scDesc, sizeof(DXGI_SWAP_CHAIN_DESC));
    scDesc.BufferCount = 1;
    scDesc.BufferDesc.Width = 800;
    scDesc.BufferDesc.Height = 600;
    scDesc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    scDesc.BufferDesc.RefreshRate.Numerator = 60;
    scDesc.BufferDesc.RefreshRate.Denominator = 1;
    scDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    scDesc.OutputWindow = hwnd_;
    scDesc.SampleDesc.Count = 1;
    scDesc.SampleDesc.Quality = 0;
    scDesc.Windowed = TRUE;

    IDXGISwapChain* pSwapChain;
    pFactory->CreateSwapChain(pDevice_, &scDesc, &pSwapChain);

    ID3D11Texture2D* pBackBuffer;
    pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)&pBackBuffer);
    pDevice_->CreateRenderTargetView(pBackBuffer, nullptr, &pRenderTargetView_);
    pBackBuffer->Release();
    pSwapChain->Release();
    pFactory->Release();

    pDeviceContext_->OMSetRenderTargets(1, &pRenderTargetView_, nullptr);

    D2D1_FACTORY_OPTIONS options;
    ZeroMemory(&options, sizeof(D2D1_FACTORY_OPTIONS));

    D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, options, &pD2DFactory_);
    // pD2DFactory_->CreateDxgiSurfaceRenderTarget(pBackBuffer, D2D1::RenderTargetProperties(D2D1_RENDER_TARGET_TYPE_HARDWARE, D2D1::PixelFormat(DXGI_FORMAT_UNKNOWN, D2D1_ALPHA_MODE_PREMULTIPLIED)), &pD2DRenderTarget_);

    DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory), reinterpret_cast<IUnknown**>(&pDWriteFactory_));
    pDWriteFactory_->CreateTextFormat(L"Arial", nullptr, DWRITE_FONT_WEIGHT_NORMAL, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 20.0f, L"en-us", &pTextFormat_);
    pD2DRenderTarget_->SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_DEFAULT);
    pD2DRenderTarget_->SetTextRenderingParams(nullptr);

    return TRUE;
}