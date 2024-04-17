// FartInjector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <vector>
#include <string>

#include "shellcode.h"

void PrintProcessNameAndID(DWORD processID);
BOOL CALLBACK EnumWindowCallback(HWND hwnd, LPARAM lParam);


LRESULT CALLBACK WindowProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
    // define window class
    WNDCLASSEX wc;
    ZeroMemory(&wc, sizeof(WNDCLASSEX));

    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WindowProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = hInstance;
    wc.hIcon = NULL;
    wc.hCursor = LoadCursor(NULL, IDC_NO);
    wc.hbrBackground;
    wc.lpszMenuName;
    wc.lpszClassName = L"FartInjectorWindowClass";
    wc.hIconSm;

    // register the window class
    RegisterClassEx(&wc);

    RECT wr = { 0, 0, 800, 600 };
    HWND hwnd;

    // create the window and use the result as the handle
    hwnd = CreateWindowExW(
        NULL, //( WS_EX_TOPMOST | WS_EX_NOACTIVATE),
        wc.lpszClassName,    // name of the window class
        L"Fart Injector",   // title of the window
        WS_OVERLAPPEDWINDOW,    // window style //WS_POPUP
        300,    // x-position of the window
        300,    // y-position of the window
        wr.right - wr.left,    // width of the window
        wr.bottom - wr.top,    // height of the window
        NULL,    // we have no parent window, NULL
        NULL,    // we aren't using menus, NULL
        hInstance,    // application handle
        NULL);    // used with multiple windows, NULL
    ShowWindow(hwnd, nCmdShow); // make sure window is shown

    AllocConsole();
    SetConsoleTitleW(L"DEBUG OUTPUT");

    typedef FILE* PFILE;
    PFILE fin, fout, ferr;
    freopen_s(&fin, "CONIN$", "r", stdin);
    freopen_s(&fout, "CONOUT$", "w", stdout);
    freopen_s(&ferr, "CONOUT$", "w", stderr);
    printf("yoo!\n");

    MSG msg{};
    while (true && !GetAsyncKeyState(VK_ESCAPE))
    {
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);

            if (msg.message == WM_QUIT)
                break;
        }
    }


    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;


    if (!K32EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        return 1;
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            PrintProcessNameAndID(aProcesses[i]);
        }
    }

    std::cout << "\n\n\n";

    std::vector<DWORD> pids;
    EnumWindows(EnumWindowCallback, (LPARAM)(&pids));

    DWORD selection = 0;
    std::cout << "Target: ";
    std::cin >> selection;
    
    HANDLE processHandle = NULL;
    if (!(selection < pids.size()))
    {
        std::cout << "<unknown target>\n";
        DebugBreak();
        return 2;
    }

    std::cout << "<targetting : " << pids.at(selection) << ">\n";
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pids.at(selection));

    if (processHandle == NULL)
    {
        std::cout << "Error opening process handle\n";
        DebugBreak();
        return 3;
    }
    
    const char* szGetProcAddress = "GetProcAddress\0";
    const char* szLoadLibraryW = "LoadLibraryA\0";

    void* shellcodeMem = VirtualAllocEx(processHandle, NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    void* szGetProcAddressMem = VirtualAllocEx(processHandle, NULL, sizeof(szGetProcAddress), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    void* szLoadLibraryWMem = VirtualAllocEx(processHandle, NULL, sizeof(szLoadLibraryW), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    
    if (shellcodeMem == nullptr || szGetProcAddressMem == nullptr || szLoadLibraryWMem == nullptr)
    {
        std::cout << "Error allocating memory in target process\n";
        DebugBreak();
        return 4;
    }

    std::cout << "started nuking at <" << (void*)((DWORD64)shellcodeMem + sizeof(void*) * 2) << ">\n";

    WriteProcessMemory(processHandle, shellcodeMem, shellcode, sizeof(shellcode), NULL);
    WriteProcessMemory(processHandle, shellcodeMem, &szGetProcAddressMem, sizeof(void*), NULL);
    WriteProcessMemory(processHandle, (void*)((DWORD64)shellcodeMem + sizeof(void*)), &szLoadLibraryWMem, sizeof(void*), NULL);

    WriteProcessMemory(processHandle, szGetProcAddressMem, szGetProcAddress, strlen(szGetProcAddress), NULL);
    WriteProcessMemory(processHandle, szLoadLibraryWMem, szLoadLibraryW, strlen(szLoadLibraryW), NULL);

    CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD64)shellcodeMem + sizeof(void*)*2), NULL, 0, NULL);

    CloseHandle(processHandle);

    return 0;
}

void PrintProcessNameAndID(DWORD processID)
{
    TCHAR szProcessName[MAX_PATH] = L"<unkown>";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

    if (NULL != hProcess)
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if (K32EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
        {
            K32GetModuleBaseNameW(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
        }
        wprintf(L"%s  (PID: %u)\n", szProcessName, processID);

        CloseHandle(hProcess);
    }
}

BOOL CALLBACK EnumWindowCallback(HWND hwnd, LPARAM lParam)
{
    const DWORD TITLE_SIZE = 1024;
    WCHAR windowTitle[TITLE_SIZE];
    memset(windowTitle, 0x0, TITLE_SIZE);

    GetWindowTextW(hwnd, windowTitle, TITLE_SIZE - 1);

    int length = GetWindowTextLengthW(hwnd);
    std::wstring title(windowTitle);

    if (!IsWindowVisible(hwnd) || length == 0 || title == L"Program Manager")
    {
        return TRUE;
    }

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == 0) return TRUE;

    static int windowCount = 0;
    std::wcout << L"[" << windowCount << L"] ";
    PrintProcessNameAndID(pid);
    std::wcout << L" " << title << L"\n";
    windowCount++;
    (*(std::vector<DWORD>*)(lParam)).push_back(pid);
    return TRUE;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_PAINT:
    {
        PAINTSTRUCT paint;
        HDC hdc = BeginPaint(hwnd, &paint);
        if (hdc)
        {
            GrayStringA(
                hdc,
                NULL,
                NULL,
                (LPARAM)"hello",
                5,
                100,
                100,
                20,
                20
            );

            EndPaint(hwnd, &paint);
        }
        return 0;
        break;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
        break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}