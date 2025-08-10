#pragma once

#include "network_session.hpp"

#include <string>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <sodium.h>
#include <memory>

class Server
{
public:
    Server(const uint16_t port);
    ~Server();

    void Start();
    void Stop(bool dumpLog = false);

private:
    struct ClientInfo
    {
        std::string username;
        std::unique_ptr<NetworkSession> session;
        unsigned char client_pk[crypto_box_PUBLICKEYBYTES];
        int fd;
        bool registered{ false };
        bool key_exchanged{ false };
    };

    std::unordered_map<int, ClientInfo> m_clients;
    std::unordered_set<std::string> m_usernames;
    std::mutex m_clientsMutex;

    int m_listenfd{ -1 };
    int m_epollfd{ -1 };

    const uint16_t m_port;

    bool m_running{ false };

    unsigned char m_server_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char m_server_sk[crypto_box_SECRETKEYBYTES];
    unsigned char m_group_key[crypto_secretbox_KEYBYTES];

private:
    void SetupListener();
    void SetNonBlocking(int fd);
    void EventLoop();
    void HandleNewConnection();
    void HandleClientEvent(ClientInfo& client, uint32_t events);
    void BroadcastEncrypted(const std::string& msg);
    void DisconnectClient(ClientInfo& client);
    bool SendSecretbox(NetworkSession* sess, const std::string& msg);
};
