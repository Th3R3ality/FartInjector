#pragma once
#include <Windows.h>
#include <iostream>
#include "shellcodes.h"

namespace method2
{
    bool inject(const char* dllPath, DWORD targetPid)
    {
        HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
        void* dllPathMem = VirtualAllocEx(processHandle, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        WriteProcessMemory(processHandle, dllPathMem, dllPath, strlen(dllPath), NULL);
        auto k32 = GetModuleHandleA("kernel32.dll");
        auto LLA = GetProcAddress(k32, "LoadLibraryA");
        HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)LLA, dllPathMem, 0, NULL);
        DWORD exitCode = STILL_ACTIVE;
        while (exitCode == STILL_ACTIVE)
        {
            GetExitCodeThread(remoteThread, &exitCode);
        }
        VirtualFreeEx(processHandle, dllPathMem, strlen(dllPath), MEM_RESET);
        CloseHandle(processHandle);

        if (processHandle == NULL)
        {
            std::cout << "Error opening process handle\n";
            return false;
        }

        void* dllPathMem = VirtualAllocEx(processHandle, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

        if (dllPathMem == nullptr)
        {
            std::cout << "Error allocating memory in target process\n";
            CloseHandle(processHandle);
            return false;
        }

        WriteProcessMemory(processHandle, dllPathMem, dllPath, strlen(dllPath), NULL);

        auto k32 = GetModuleHandleA("kernel32.dll");
        if (!k32)
        {
            std::cout << "Error getting kernel32.dll\n";
            CloseHandle(processHandle);
            return false;
        }
        auto LLA = GetProcAddress(k32, "LoadLibraryA");
        if (!LLA)
        {
            std::cout << "Error getting LoadLibraryA\n";
            CloseHandle(processHandle);
            return false;
        }

        HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)LLA, dllPathMem, 0, NULL);

        if (remoteThread == NULL)
        {
            std::cout << "Error creating remote thread\n";
            CloseHandle(processHandle);
            return false;
        }

        DWORD exitCode = STILL_ACTIVE;
        while (exitCode == STILL_ACTIVE)
        {
            GetExitCodeThread(remoteThread, &exitCode);
        }

        VirtualFreeEx(processHandle, dllPathMem, strlen(dllPath), MEM_RESET);

        CloseHandle(processHandle);
    }
}

namespace method1
{
    bool inject(const char* dllPath, DWORD targetPid)
    {
        HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
        if (processHandle == NULL)
        {
            std::cout << "Error opening process handle\n";
            return false;
        }

        const char* szGetProcAddress = "GetProcAddress\0";
        const char* szLoadLibraryW = "LoadLibraryA\0";
        const char* szDllPath = dllPath;

        void* shellcodeMem = VirtualAllocEx(processHandle, NULL, sizeof(method1::shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        void* szGetProcAddressMem = VirtualAllocEx(processHandle, NULL, strlen(szGetProcAddress), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        void* szLoadLibraryWMem = VirtualAllocEx(processHandle, NULL, strlen(szLoadLibraryW), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        void* szDllPathMem = VirtualAllocEx(processHandle, NULL, strlen(szDllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

        if (szDllPathMem == nullptr || shellcodeMem == nullptr || szGetProcAddressMem == nullptr || szLoadLibraryWMem == nullptr)
        {
            std::cout << "Error allocating memory in target process\n";
            CloseHandle(processHandle);
            DebugBreak();
            return false;
        }

        std::cout << "started nuking at <" << (void*)((DWORD64)shellcodeMem + sizeof(void*) * 3) << ">\n";

        WriteProcessMemory(processHandle, shellcodeMem, shellcode, sizeof(shellcode), NULL);
        WriteProcessMemory(processHandle, shellcodeMem, &szDllPathMem, sizeof(void*), NULL);
        WriteProcessMemory(processHandle, (void*)((DWORD64)shellcodeMem + sizeof(void*) * 1), &szGetProcAddressMem, sizeof(void*), NULL);
        WriteProcessMemory(processHandle, (void*)((DWORD64)shellcodeMem + sizeof(void*) * 2), &szLoadLibraryWMem, sizeof(void*), NULL);

        WriteProcessMemory(processHandle, szDllPathMem, szDllPath, strlen(szDllPath), NULL);
        WriteProcessMemory(processHandle, szGetProcAddressMem, szGetProcAddress, strlen(szGetProcAddress), NULL);
        WriteProcessMemory(processHandle, szLoadLibraryWMem, szLoadLibraryW, strlen(szLoadLibraryW), NULL);


#ifdef NDEBUG
        std::cout << "press <Enter> to execute shellcode\n";
        while (!GetAsyncKeyState(VK_RETURN)) {};
#endif

#ifdef _DEBUG
        std::cout << "DebugBreak before shellcode execution\n";
        DebugBreak();
#endif // _DEBUG

        CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD64)shellcodeMem + sizeof(void*) * 3), NULL, 0, NULL);

        CloseHandle(processHandle);
        return true;
    }
}

