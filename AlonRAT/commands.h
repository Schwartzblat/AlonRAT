#pragma once
#include "TCPClient.h"
#include "utils.h"
#include "AutoHandle.h"

void handle_ping_command(TCPClient client);

void handle_shell_command(TCPClient client);

void handle_shell_command_as_user(TCPClient client);

void download_file(TCPClient client);

void upload_file(TCPClient client);
