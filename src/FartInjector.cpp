// FartInjector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <vector>
#include <string>

void PrintProcessNameAndID(DWORD processID);
BOOL CALLBACK EnumWindowCallback(HWND hwnd, LPARAM lParam);

int main()
{
    std::cout << "Hello World!\n";

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
    
    HANDLE processHandle = 0;
    if (selection < pids.size())
    {
        //processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pids.at(selection));
        std::cout << "<targetting : " << pids.at(selection) << ">\n";
    }
    else
    {
        std::cout << "<unknown target>\n";
    }

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