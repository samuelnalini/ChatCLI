#pragma once

#include "ncursesUI.hpp"
#include "network_session.hpp"
#include <sodium/crypto_box.h>
#include <sodium/crypto_secretbox.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <sodium.h>

class Client
{
public:
    Client(std::string ip = "127.0.0.1", int port = 8080);
    ~Client();

    void Start();
    void Stop(bool dumpLog = false);

private:
    std::unique_ptr<NetworkSession> m_session;

    unsigned char m_client_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char m_client_sk[crypto_box_SECRETKEYBYTES];
    unsigned char m_server_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char m_group_key[crypto_secretbox_KEYBYTES];

    NcursesUI m_ui;

    std::vector<std::thread> m_threadPool;

    std::string m_ip;
    int         m_port;

    std::string m_username;

    std::atomic<bool> m_stopping{ false };
    std::atomic<bool> m_running{ false };
    std::atomic<bool> m_uiActive{ false };
    std::string       m_exitReason{ "None" };
    std::mutex        m_netMutex;

private:
    bool CreateSession();
    void CloseSession();

    bool ChangeUsername();

    bool SendEncrypted(const std::string& plaintext);
    std::optional<std::string> RecvDecrypted();

    void ClientLoop();
    void UIUpdateLoop();
    void HandleBroadcast();
};
