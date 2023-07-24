#include "pch.h"

#ifndef CyberWindow_H
#define CyberWindow_H

#include <Windows.h>
#include <vector>
#include <string>


#include <d2d1_1.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <string>
#include <vector>
#include <DirectXColors.h>
#include <d2d1helper.h>
#include <dwrite.h>


namespace CyberWindow {

    struct StringOverlay {
        std::wstring text;
        int x;
        int y;
    };

    class TextRenderer {
    public:
        TextRenderer(HINSTANCE hInstance);
        ~TextRenderer();

        void RenderTextUsingDirect2D(int x, int y, const std::wstring& text);
        BOOL InitializeAndRender();

        void AddOverlay(const std::wstring& text, int x, int y);
        void UpdateOverlayPosition(size_t index, int x, int y);
        void RemoveOverlay(size_t index);

    private:
        HINSTANCE hInstance_;
        HWND hwnd_;
        ID3D11Device* pDevice_ = nullptr;
        ID3D11DeviceContext* pDeviceContext_ = nullptr;
        ID3D11RenderTargetView* pRenderTargetView_ = nullptr;
        IDWriteFactory* pDWriteFactory_ = nullptr;
        IDWriteTextFormat* pTextFormat_ = nullptr;
        ID2D1Factory* pD2DFactory_ = nullptr;
        ID2D1RenderTarget* pD2DRenderTarget_ = nullptr;
        std::vector<StringOverlay> overlays_;

        BOOL CreateWindowAndDirectX();
    };
}

#endif