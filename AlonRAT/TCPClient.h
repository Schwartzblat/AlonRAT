#pragma once
#include <WS2tcpip.h>
#include <iostream>
#include <string>
#include "utils.h"

#pragma comment (lib, "ws2_32.lib")

class TCPClient {
private:
    SOCKET m_sockfd;
    const char* m_ip_address;
    int m_port;

public:
    bool m_is_connected;

    TCPClient(const char* ip_address, const int port);

    ~TCPClient();

    void reconnect();

    void send_data(const char* data);

    const std::shared_ptr<char*> receive();

    const std::shared_ptr<char*> receive(int size);

    void disconnect();
};