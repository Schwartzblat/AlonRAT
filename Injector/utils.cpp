#include "utils.h"

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
    //IMAGE_DATA_DIRECTORY exportDir = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    // Calculate the address of the export directory
    IMAGE_EXPORT_DIRECTORY* exportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>((uintptr_t)module_base + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

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
        }
        else if (strcmp(functionName, OBFUSCATE("LoadLibraryA")) == 0) {
            load_library = reinterpret_cast<load_library_type>(functionAddress);
        }
    }
}


FARPROC resolve_winapi(const char* dll_name, const char* func_name) {
    HMODULE module = load_library(dll_name);
    return get_proc_address(module, func_name);
}