#include "TCPClient.h"


TCPClient::TCPClient(const char* ip_address, const int port)
    : m_sockfd(0),
    m_ip_address(ip_address),
    m_port(port)
{}

TCPClient::~TCPClient() {
    closesocket(m_sockfd);
    WSACleanup();
}

void TCPClient::reconnect() {
    sockaddr_in server_addr;
    WSADATA wsData;
    if (WSAStartup(MAKEWORD(2, 2), &wsData) != 0) {
        return;
    }
    m_sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_sockfd == INVALID_SOCKET) {
        WSACleanup();
        return;
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(m_port);
    inet_pton(AF_INET, m_ip_address, &server_addr.sin_addr);

    if (connect(m_sockfd, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        closesocket(m_sockfd);
        WSACleanup();
    }
}

void TCPClient::send_data(const char* data) {
    int bytes_sent = send(m_sockfd, data, static_cast<int>(strlen(data)), 0);
    if (bytes_sent == SOCKET_ERROR) {
        closesocket(m_sockfd);
        WSACleanup();
    }
}

const std::shared_ptr<char*> TCPClient::receive() {
    char size[4];
    int bytes_received = recv(m_sockfd, size, 4, 0);
    if (bytes_received == SOCKET_ERROR) {
        closesocket(m_sockfd);
        WSACleanup();
    }
    auto data = std::make_shared<char*>(new char[*reinterpret_cast<uint32_t*>(size)]);
    recv(m_sockfd, *data, *reinterpret_cast<uint32_t*>(size), 0);
    return data;
}

const std::shared_ptr<char*> TCPClient::receive(int size) {
    auto data = std::make_shared<char*>(new char[size]);
    recv(m_sockfd, *data, size, 0);
    return data;
}

void TCPClient::disconnect() {
    closesocket(m_sockfd);
    WSACleanup();
}