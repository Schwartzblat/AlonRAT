#pragma once
#include <string>
#include <WS2tcpip.h>
#include <windows.h>
#include "obfuscate.h"
#include "windows_structs.h"


typedef HMODULE(WINAPI* load_library_type)(LPCSTR lpLibFileName);

typedef FARPROC(WINAPI* get_proc_address_type)(HMODULE hModule, LPCSTR lpProcName);
typedef int (WINAPI* message_box_type)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
typedef HANDLE(WINAPI* open_process_type)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
typedef HMODULE(WINAPI* get_module_handle_type)(LPCWSTR lpModuleName);
typedef HMODULE(WINAPI* virtual_alloc_ex_type)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

std::string exec(const char* cmd);

const std::string domain_to_ip(const char* domain);

void initilize_winapi();
