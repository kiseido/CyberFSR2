#include "pch.h"
#include "InterposerWindow.h"
#include "CI_Logging.h"

#include "resource.h"

#include <CommCtrl.h>
#pragma comment(lib, "ComCtl32.lib")


inline InterposerWindow InterposerWindow::instance;

InterposerWindow::InterposerWindow() : hWindow(NULL), hButton(NULL), hTextBox(NULL), hInstance(NULL), showWindow(false), WindowThread() {
}

InterposerWindow::~InterposerWindow() {
  // end thread and window?
}

void InterposerWindow::OnStringUpdated(const std::wstring_view& input, const SIZE_T index, const SIZE_T length) {
    // Post the custom message to update the ListView in the main thread.
    // The LPARAM will be the index of the updated string and WPARAM will be the length.
    PostMessage(instance.hWindow, WM_USER_UPDATE_LISTVIEW, (WPARAM)length, (LPARAM)index);
}

void InterposerWindow::InitListView() {
    HWND hListView = GetDlgItem(hWindow, IDC_LIST1);

    // Initialize columns for ListView. Assuming you just want one column for the strings.
    LVCOLUMNW lvColumn;
    memset(&lvColumn, 0, sizeof(lvColumn));
    lvColumn.mask = LVCF_TEXT | LVCF_WIDTH;
    lvColumn.cx = 500; // Assuming a fixed width for simplicity. Adjust accordingly.
    lvColumn.pszText = const_cast<LPWSTR>(L"Logs");
    ListView_InsertColumn(hListView, 0, &lvColumn);

    // Populate initial data from recallWindow
    auto& recallWindow = CyberInterposer::logger.recallWindow;
    auto lines = recallWindow.GetLines();

    LVITEMW lvItem;
    memset(&lvItem, 0, sizeof(lvItem));
    lvItem.mask = LVIF_TEXT;

    int i = 0;
    for (const auto& line : lines) {
        lvItem.iItem = i++;
        lvItem.pszText = const_cast<LPWSTR>(line.c_str());
        ListView_InsertItem(hListView, &lvItem);
    }

    recallWindow.addListener(InterposerWindow::OnStringUpdated);
}


void KillGame(auto input, bool askFirst = true) {
    if (askFirst) {
        int msgboxID = MessageBox(
            input,
            "Are you sure you want to terminate the game and Interposer?",
            "Confirmation",
            MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2
        );

        if (msgboxID == IDNO) {
            // If the user says no, we simply return without terminating
            return;
        }
    }

    DWORD dwParentProcessId = GetCurrentProcessId();
    HANDLE hParentProcess = OpenProcess(PROCESS_TERMINATE, FALSE, dwParentProcessId);
    if (hParentProcess) {
        TerminateProcess(hParentProcess, 0);
        CloseHandle(hParentProcess);
    }
    else {
        // Error handling, to understand if OpenProcess fails
        DWORD error = GetLastError();
        std::string errorMsg = "OpenProcess failed with error: " + std::to_string(error);
        MessageBox(input, errorMsg.c_str(), "Error", MB_ICONERROR);
    }
}

INT_PTR CALLBACK DialogProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    auto& instance = InterposerWindow::GetInstance();

    switch (message) {
        case WM_INITDIALOG: {
            SetTimer(hwnd, InterposerWindow::WM_USER_Update_Window, 10000, nullptr);
            instance.InitListView();
            return 0;  // Let the system set the keyboard focus
        }
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDCLOSE: {
                    KillGame(hwnd);
                    return TRUE;
                }
            }
            break;
        }
        case WM_TIMER: {
            if (wParam == InterposerWindow::WM_USER_Update_Window) {
                //DoUpdateWindow(*window);
                return 0;
            }
            break;
        }
        case WM_CLOSE: {
            EndDialog(hwnd, 0);
            return TRUE;
        }
        case InterposerWindow::WM_USER_UPDATE_LISTVIEW: {
            SIZE_T length = (SIZE_T)wParam;
            SIZE_T index = (SIZE_T)lParam;

            HWND hListView = GetDlgItem(hwnd, IDC_LIST1);
            auto& recallWindow = CyberInterposer::logger.recallWindow;
            std::wstring updatedStr = recallWindow.GetLines()[index];

            LVITEMW lvItem;
            memset(&lvItem, 0, sizeof(lvItem));
            lvItem.iSubItem = 0;
            lvItem.pszText = const_cast<LPWSTR>(updatedStr.c_str());

            SendMessage(hListView, LVM_SETITEMTEXT, index, (LPARAM)&lvItem);

            return TRUE;
        }

    };
    return FALSE;
}


DWORD WINAPI WindowThreadMain(LPVOID lpParam) {
    auto& instance = InterposerWindow::GetInstance();

    DialogBox(instance.hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL, DialogProc);

    //SetTimer(hwnd, InterposerWindow::WM_Update_Window, 10000, nullptr);

    MSG msg = {};
    while (true) {
        if (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        else {
            constexpr SIZE_T msInSecond = 1000;
            constexpr SIZE_T millisecondsToSleep = msInSecond / 200;

            const auto didSwitch = SwitchToThread();
            if(didSwitch == false)
                Sleep(millisecondsToSleep);
        }
    }
    return 0;
}

void InterposerWindow::Start(HMODULE hModule)
{
    hInstance = hModule;

    WindowThread = CreateThread(NULL, 0, WindowThreadMain, hModule, 0, NULL);
}


