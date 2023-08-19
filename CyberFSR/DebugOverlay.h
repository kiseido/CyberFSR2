#pragma once

//#define CyberFSR_DO_OVERLAY1
//#define CyberFSR_DO_OVERLAY2
//#define CyberFSR_DO_OVERLAY3

#ifdef CyberFSR_DO_OVERLAY3
namespace CyberFSROverlay {
    class Overlay {
    private:
        HWND parentWindow = NULL;
        HWND ourWindow = NULL;
        WNDCLASS windowClass = { 0 };
        static LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
        LRESULT NonStaticWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
    public:
        Overlay();
        bool setupWindowDX(ID3D12GraphicsCommandList* InCmdList);
        bool setupWindow();
        bool Draw();
    };
}
#endif

#ifdef CyberFSR_DO_OVERLAY2
#include <windows.h>
#include <string>
#include <chrono>
#include <thread>
#include <iomanip>

namespace CyberFSROverlay {
    extern HANDLE overlay;

    LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

    void DisplayTimeOnWindow();
}
#endif


#ifdef CyberFSR_DO_OVERLAY1
#include <Windows.h>
#include <d2d1.h>
#include <dwrite.h>
#include <string>
#include <unordered_map>
#include <memory>

class DebugOverlay {
private:
    HWND targetWindow = nullptr;
    ID2D1Factory* d2dFactory = nullptr;
    ID2D1HwndRenderTarget* d2dRenderTarget = nullptr;
    IDWriteFactory* dwFactory = nullptr;
    IDWriteTextFormat* textFormat = nullptr;

    bool InitializeResources();
    void ReleaseResources();

public:
    struct LayerPhysical {
        POINT position = { 0, 0 };
        POINT padding = { 0, 0 };
        POINT margin = { 0, 0 };
    };

    struct LayerVisual {
        COLORREF textColour = RGB(0, 0, 0);
        COLORREF outlineColour = RGB(0, 0, 0);
        COLORREF backgroundColour = RGB(0, 0, 0);
        float outlineThickness = 0.0f;
    };

    struct Layer {
        const wchar_t* type;

        std::shared_ptr<LayerPhysical> body;
        std::shared_ptr<LayerVisual> style;

        virtual ~Layer() = default;
        Layer(const wchar_t* typein) : type(typein) {};
    };

    struct TextLayer : Layer {
        static const wchar_t TextType[];

        wchar_t text[128];

        TextLayer() : Layer(TextType), text() {};
    };

    struct LayerTreeNode : Layer {
        static const wchar_t TreeNodeType[];

        std::unordered_map<int, std::shared_ptr<Layer>> children;

        void AddChild(int id, std::shared_ptr<Layer> layer);
        bool RemoveChild(int id);
        std::shared_ptr<Layer> GetChild(int id);

        LayerTreeNode() : Layer(TreeNodeType) {};
    };

    LayerTreeNode OverlayTree;

    DebugOverlay();
    ~DebugOverlay();

    void Render();
};

#endif