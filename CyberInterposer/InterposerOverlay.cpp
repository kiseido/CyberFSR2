#include "pch.h"
#include "InterposerOverlay.h"


bool Overlay::IsOverlaySequenceDown() {
    return (GetAsyncKeyState(VK_BACK) & 0x8000) &&
        (GetAsyncKeyState(VK_CONTROL) & 0x8000) &&
        (GetAsyncKeyState(VK_MENU) & 0x8000);
}