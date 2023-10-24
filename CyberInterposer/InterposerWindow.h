#pragma once

class InterposerWindow {
public:
    static InterposerWindow& GetInstance() {
        return instance;
    }

    void Start(HMODULE hModule);


    static void OnStringUpdated(const std::wstring_view& input, const SIZE_T index, const SIZE_T length);

private:
    InterposerWindow();
    ~InterposerWindow();
    InterposerWindow(const InterposerWindow&) = delete;
    InterposerWindow& operator=(const InterposerWindow&) = delete;

    void InitListView();

    friend DWORD WINAPI WindowThreadMain(LPVOID lpParam);
    friend LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    friend void DoUpdateWindow(InterposerWindow&);
    friend INT_PTR CALLBACK DialogProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

    std::atomic<bool> showWindow;
    
    HANDLE WindowThread;

    HWND hWindow;
    HWND hButton;
    HWND hTextBox;
    HINSTANCE hInstance;

    static InterposerWindow instance;

    enum WindowsMessaging {
        Enum_Base = WM_USER,
        CONTROLS_ID_Offset = 2000,
        MESSAGES_ID_Offset = 4000,

        WM_USER_StartOfMessages = Enum_Base + MESSAGES_ID_Offset,
        WM_USER_Update_Window,
        WM_USER_UPDATE_LISTVIEW,

        IDC_StartofUI = Enum_Base + CONTROLS_ID_Offset,
        IDC_BUTTON,
        IDC_TEXTBOX,
    };
};