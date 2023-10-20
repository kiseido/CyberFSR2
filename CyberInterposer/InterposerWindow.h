#pragma once

class InterposerWindow {
public:
    static InterposerWindow& GetInstance() {
        return instance;
    }

    void Show(int nCmdShow);

    void StartWindowThread();
    void UpdateTime();

private:
    InterposerWindow();
    ~InterposerWindow() = default;
    InterposerWindow(const InterposerWindow&) = delete;
    InterposerWindow& operator=(const InterposerWindow&) = delete;

    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    LRESULT instanceWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

    void InitWindow();


    std::thread windowThread;

    HWND hwnd;
    HWND hTextBox;
    HINSTANCE hInstance;

    static InterposerWindow instance;

    static constexpr UINT WM_UPDATE_TIME = WM_USER + 1;
    static constexpr UINT IDC_BUTTON_ADDTIME = WM_USER + 2;
    static constexpr UINT IDC_TEXTBOX = WM_USER + 3;
};