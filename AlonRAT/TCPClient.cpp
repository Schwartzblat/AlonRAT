#include "TCPClient.h"


TCPClient::TCPClient(const char* ip_address, const int port)
    : m_sockfd(0),
    m_ip_address(ip_address),
    m_port(port),
    m_is_connected(false)
{}

TCPClient::~TCPClient() {
    WINAPI_OBFUSCATE(close_socket_type, "closesocket", "ws2_32")(m_sockfd);
    WINAPI_OBFUSCATE(wsa_cleanup_type, "WSACleanup", "ws2_32")();
}

void TCPClient::reconnect() {
    wsa_startup_type wsa_startup = WINAPI_OBFUSCATE(wsa_startup_type, "WSAStartup", "ws2_32");
    wsa_cleanup_type wsa_cleanup = WINAPI_OBFUSCATE(wsa_cleanup_type, "WSACleanup", "ws2_32");
    sockaddr_in server_addr;
    WSADATA wsData;
    if (wsa_startup(MAKEWORD(2, 2), &wsData) != 0) {
        return;
    }
    m_sockfd = WINAPI_OBFUSCATE(socket_type, "socket", "ws2_32")(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_sockfd == INVALID_SOCKET) {
        wsa_cleanup();
        return;
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = WINAPI_OBFUSCATE(htons_type, "htons", "ws2_32")(m_port);
    WINAPI_OBFUSCATE(inet_pton_type, "inet_pton", "ws2_32")(AF_INET, m_ip_address, &server_addr.sin_addr);

    if (WINAPI_OBFUSCATE(connect_type, "connect", "ws2_32")(m_sockfd, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        WINAPI_OBFUSCATE(close_socket_type, "closesocket", "ws2_32")(m_sockfd);
        wsa_cleanup();
    }
    m_is_connected = true;
}

void TCPClient::send_data(const char* data) {
    int bytes_sent = WINAPI_OBFUSCATE(send_type, "send", "ws2_32")(m_sockfd, data, static_cast<int>(strlen(data)), 0);
    if (bytes_sent == SOCKET_ERROR) {
        WINAPI_OBFUSCATE(close_socket_type, "closesocket", "ws2_32")(m_sockfd);
        WINAPI_OBFUSCATE(wsa_cleanup_type, "WSACleanup", "ws2_32")();
    }
}

const std::shared_ptr<char*> TCPClient::receive() {
    char size[4];
    int bytes_received = WINAPI_OBFUSCATE(recv_type, "recv", "ws2_32")(m_sockfd, size, 4, 0);
    if (bytes_received == SOCKET_ERROR) {
        WINAPI_OBFUSCATE(close_socket_type, "closesocket", "ws2_32")(m_sockfd);
        WINAPI_OBFUSCATE(wsa_cleanup_type, "WSACleanup", "ws2_32")();
    }
    auto data = std::make_shared<char*>(new char[*reinterpret_cast<uint32_t*>(size)]);
    WINAPI_OBFUSCATE(recv_type, "recv", "ws2_32")(m_sockfd, *data, *reinterpret_cast<uint32_t*>(size), 0);
    return data;
}

const std::shared_ptr<char*> TCPClient::receive(int size) {
    auto data = std::make_shared<char*>(new char[size]);
    WINAPI_OBFUSCATE(recv_type, "recv", "ws2_32")(m_sockfd, *data, size, 0);
    return data;
}

void TCPClient::disconnect() {
    m_is_connected = false;
    WINAPI_OBFUSCATE(close_socket_type, "closesocket", "ws2_32")(m_sockfd);
    WINAPI_OBFUSCATE(wsa_cleanup_type, "WSACleanup", "ws2_32")();
}