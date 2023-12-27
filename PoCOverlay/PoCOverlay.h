// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the POCOVERLAY_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// POCOVERLAY_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef POCOVERLAY_EXPORTS
#define POCOVERLAY_API __declspec(dllexport)
#else
#define POCOVERLAY_API __declspec(dllimport)
#endif

// This class is exported from the dll
class POCOVERLAY_API CPoCOverlay {
public:
	CPoCOverlay(void);
	// TODO: add your methods here.
};

extern POCOVERLAY_API int nPoCOverlay;

POCOVERLAY_API int fnPoCOverlay(void);

#include <d3d12.h>
#include <wrl.h>
#include <Windows.h>
#include <imgui.h>

class Overlay {
public:
    Overlay(HWND hWnd);
    void Render();

private:
    HWND m_hWnd;
    float m_positionX, m_positionY, m_velocityX, m_velocityY;
    Microsoft::WRL::ComPtr<ID3D12Device> m_device;
    Microsoft::WRL::ComPtr<ID3D12DescriptorHeap> m_srvHeap;

    void Initialize();
    RECT GetWindowDimensions();
};

