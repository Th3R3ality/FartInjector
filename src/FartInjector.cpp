#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <vector>
#include <string>

#include "methods.h"
#include "shellcodes.h"

void PrintProcessNameAndID(DWORD processID);
BOOL CALLBACK EnumWindowCallback(HWND hwnd, LPARAM lParam);

int main( int argc, char** argv)
{
    if (argc <= 1)
    {
        std::cout << "low arg count\n";
        DebugBreak();
        return -1;
    }

    printf("yoo!\n\n");


    for (int idx = 0; idx < argc; idx++)
    {
        std::cout << argv[idx] << "\n";
    }
    std::cout << std::endl;

    //DWORD aProcesses[1024], cbNeeded, cProcesses;
    //unsigned int i;

    //if (!K32EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    //{
    //    DebugBreak();
    //    return 1;
    //}

    //cProcesses = cbNeeded / sizeof(DWORD);

    //for (i = 0; i < cProcesses; i++)
    //{
    //    if (aProcesses[i] != 0)
    //    {
    //        //PrintProcessNameAndID(aProcesses[i]);
    //    }
    //}

    std::cout << "\n\n\n";

    std::vector<DWORD> pids;
    EnumWindows(EnumWindowCallback, (LPARAM)(&pids));

    std::cout << "Target: ";

    DWORD pidSelection = 0;
    std::cin >> pidSelection;
    if (!(pidSelection < pids.size()) || pidSelection < 0)
    {
        
        std::cout << "<unknown target>\n";
        DebugBreak();
        return 2;
    }

    std::cout << "\n<targetting : " << pids.at(pidSelection) << ">\n\n";
    
    std::cout << "        >Injection Method<\n";
    std::cout << " [1] shellcode + CreateRemoteThread\n";
    std::cout << " [2] CreateRemoteThread @ LoadLibraryA\n";

    std::cout << ">";


    DWORD methodSelection = 0;
    std::cin >> methodSelection;

    switch (methodSelection)
    {
    case 1:
        method1::inject(argv[1], pids.at(pidSelection));
        break;
    case 2:
        method2::inject(argv[1], pids.at(pidSelection));
        break;
    default:
        std::cout << "method not found\n";
        break;
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