#pragma once
#include <WS2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <Psapi.h>

typedef decltype(LoadLibraryA)* load_library_type;
typedef decltype(GetProcAddress)* get_proc_address_type;
typedef decltype(MessageBoxA)* message_box_type;
typedef decltype(OpenProcess)* open_process_type;
typedef decltype(GetModuleHandleW)* get_module_handle_type;
typedef decltype(VirtualAllocEx)* virtual_alloc_ex_type;
typedef decltype(Sleep)* sleep_type;
typedef decltype(CloseHandle)* close_handle_type;
typedef decltype(WriteProcessMemory)* write_process_memory_type;
typedef decltype(VirtualFreeEx)* virtual_free_ex_type;
typedef decltype(CreateRemoteThread)* create_remote_thread_type;
typedef decltype(CreateToolhelp32Snapshot)* create_toolhelp_snapshot_type;
typedef decltype(Process32FirstW)* process32_first_type;
typedef decltype(Process32NextW)* process32_next_type;
typedef decltype(WSAStartup)* wsa_startup_type;
typedef decltype(WSACleanup)* wsa_cleanup_type;
typedef decltype(getaddrinfo)* get_addr_info_type;
typedef decltype(inet_ntop)* inet_ntop_type;
typedef decltype(inet_pton)* inet_pton_type;
typedef decltype(freeaddrinfo)* free_addr_info_type;
typedef decltype(CreatePipe)* create_pipe_type;
typedef decltype(GetStdHandle)* get_std_handle_type;
typedef decltype(CreateProcessA)* create_process_a_type;
typedef decltype(ReadFile)* read_file_type;
typedef decltype(GetLastError)* get_last_error_type;
typedef decltype(socket)* socket_type;
typedef decltype(closesocket)* close_socket_type;
typedef decltype(htons)* htons_type;
typedef decltype(connect)* connect_type;
typedef decltype(send)* send_type;
typedef decltype(recv)* recv_type;
typedef decltype(OpenProcessToken)* open_process_token_type;
typedef decltype(CreateProcessAsUserA)* create_process_as_user_a_type;
typedef decltype(CreateMutexA)* create_mutex_a_type;
typedef decltype(FreeLibraryAndExitThread)* free_library_and_exit_thread_type;
typedef decltype(EnumProcessModules)* enum_process_modules_type;
typedef decltype(GetModuleFileNameExA)* get_module_filename_ex_a_type;
typedef decltype(CreateThread)* create_thread_type;
typedef decltype(WaitForSingleObject)* wait_for_single_object_type;
typedef decltype(ReleaseMutex)* release_mutex_type;
typedef decltype(CreateFileA)* create_file_a_type;
typedef decltype(WriteFile)* write_file_type;
typedef decltype(ReadFile)* read_file_type;