#pragma once
#include <string>
#include <WS2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include "obfuscate.h"
#include "windows_structs.h"
#define WINAPI_OBFUSCATE(type, name, dll) reinterpret_cast<type>(resolve_winapi(OBFUSCATE(dll), OBFUSCATE(name)))


typedef HMODULE(WINAPI* load_library_type)(LPCSTR lpLibFileName);

typedef FARPROC(WINAPI* get_proc_address_type)(HMODULE hModule, LPCSTR lpProcName);
typedef int (WINAPI* message_box_type)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
typedef HANDLE(WINAPI* open_process_type)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
typedef HMODULE(WINAPI* get_module_handle_type)(LPCWSTR lpModuleName);
typedef HMODULE(WINAPI* virtual_alloc_ex_type)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef VOID(WINAPI* sleep_type)(DWORD dwMilliseconds);
typedef BOOL(WINAPI* close_handle_type)(HANDLE hObject);
typedef BOOL(WINAPI* write_process_memory_type)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
typedef BOOL(WINAPI* virtual_free_ex_type)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef HANDLE(WINAPI* create_remote_thread_type)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef HANDLE(WINAPI* create_toolhelp_snapshot_type)(DWORD dwFlags, DWORD th32ProcessID);
typedef BOOL(WINAPI* process32_first_type)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
typedef BOOL(WINAPI* process32_next_type)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);

void initilize_winapi();

FARPROC resolve_winapi(const char* dll_name, const char* func_name);