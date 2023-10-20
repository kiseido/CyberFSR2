#include "pch.h"
#include "InterposerWindow.h"

inline InterposerWindow InterposerWindow::instance;


InterposerWindow::InterposerWindow() {

}

void InterposerWindow::InitWindow() {
    const LPCSTR CLASS_NAME = "Sample Window Class";

    WNDCLASS wc = {};

    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;

    RegisterClass(&wc);

    hwnd = CreateWindowEx(
        0,
        CLASS_NAME,
        "Sample Window",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        NULL,
        NULL,
        hInstance,
        NULL
    );
}

void InterposerWindow::Show(int nCmdShow) {
    if (hwnd == 0) InitWindow();

    ShowWindow(hwnd, nCmdShow);

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

LRESULT CALLBACK InterposerWindow::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    return instance.instanceWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT InterposerWindow::instanceWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg)
    {
    case WM_CREATE: {
        CreateWindow(
            "BUTTON",
            "Add Time",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            10, 10, 100, 30,
            hwnd,
            (HMENU)IDC_BUTTON_ADDTIME,
            hInstance,
            NULL);

        hTextBox = CreateWindow(
            "EDIT",
            "",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL,
            10, 50, 280, 160,
            hwnd,
            (HMENU)IDC_TEXTBOX,
            hInstance,
            NULL);
        return 0;
    }
    case WM_COMMAND: {
        if (LOWORD(wParam) == IDC_BUTTON_ADDTIME)
        {
            std::time_t t = std::time(nullptr);
            std::tm tm;
            localtime_s(&tm, &t);
            char mbstr[100];
            std::strftime(mbstr, sizeof(mbstr), "%H:%M:%S", &tm);

            std::string timeStr = std::string("[") + mbstr + "] ";

            char buffer[1024];
            GetWindowText(hTextBox, buffer, 1024);
            std::string currentText = buffer;

            if (!currentText.empty()) {
                timeStr += "\r\n";
            }

            currentText.insert(0, timeStr); // Use insert to prepend the timeStr

            int lines = 0;
            size_t pos = currentText.size();
            while (lines < 10 && pos != std::string::npos) {
                pos = currentText.rfind("\r\n", pos);
                if (pos != std::string::npos) {
                    lines++;
                    if (lines < 10) {
                        pos--;
                    }
                }
            }
            if (lines == 10 && pos != std::string::npos) {
                currentText = currentText.substr(pos + 2);
            }

            SetWindowText(hTextBox, currentText.c_str());
        }
        return 0;
    }
    case WM_DESTROY: {
        PostQuitMessage(0);
        return 0;
    }
    case WM_UPDATE_TIME: {
        std::time_t t = std::time(nullptr);
        std::tm tm;
        localtime_s(&tm, &t);
        char mbstr[100];
        std::strftime(mbstr, sizeof(mbstr), "%H:%M:%S", &tm);
        std::string timeStr = std::string("[") + mbstr + "]";

        SetWindowText(hTextBox, timeStr.c_str());
        return 0;
    }
    }


    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}


void InterposerWindow::StartWindowThread() {
    windowThread = std::thread([this]() {
        // Wait for 1 second
        std::this_thread::sleep_for(std::chrono::seconds(12));

        // Show the window
        Show(SW_SHOW);

        // Update the time every second
        while (true) {
            UpdateTime();
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        });
}

void InterposerWindow::UpdateTime() {
    PostMessage(hwnd, WM_UPDATE_TIME, 0, 0);
}