#include "headers/client.hpp"
#include "debug.hpp"
#include "common.hpp"

#include <chrono>
#include <iostream>
#include <ncurses.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_secretbox.h>
#include <stdexcept>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sodium.h>

Client::Client(std::string ip, int port)
    : m_ip(std::move(ip))
    , m_port(port)
    , m_ui()
{}

Client::~Client()
{
    if (m_running)
    {
        m_exitReason = "Abrupt exit -> attempting graceful shutdown";
        Stop(true);
    }
};

bool Client::ChangeUsername()
{
    try
    {
        bool valid{ false };

        while (!valid)
        {
            auto usernameOpt{ m_ui.PromptInput("Username: ") };

            if (!usernameOpt.has_value() || usernameOpt->empty())
            {
                continue;
            }

            if (usernameOpt->length() > MAX_USERNAME_LEN)
            {
                m_ui.PushPriorityMessage("Username too long, try again");
                continue;
            }

            const std::string username{ *usernameOpt };

            if (username == "/exit")
            {
                throw std::runtime_error("User quit");
            }

            if (!SendEncrypted(username))
            {
                Debug::Log("Invalid username " + username);
                throw std::runtime_error("Failed to send username");
            }
            
            auto response = RecvDecrypted();
            
            if (!response)
            {
                Debug::Log("Failed to receive response -> Recovering", Debug::LOG_LEVEL::WARNING);
                m_ui.PushPriorityMessage("An error has occurred, please try again");
                continue;
            }

            if (response == "SERVER::USERNAME_TAKEN")
            {
                m_ui.PushPriorityMessage("User '" + username + "' already exists");
                continue;
            }
            else if (response == "SERVER::USERNAME_INVALID")
            {
                m_ui.PushPriorityMessage("Invalid username, please try again");
                continue;
            }

            m_username = username;
            valid = true;
            break;
        }
    }
    catch (std::exception& e)
    {
        Debug::Log(e.what(), Debug::LOG_LEVEL::ERROR);
        return false; 
    }

    return true;
}

void Client::Start()
{
    if (m_running)
        return;

    try
    {
        if (!CreateSession())
        {
            throw std::runtime_error("Failed to create session -> stopping");
            exit(1);
        }
       
        m_uiActive = true;
        m_ui.Init();
       
        Debug::Log("[*] Client started...");

        // Encryption Handshake

        crypto_box_keypair(m_client_pk, m_client_sk);

        // Send PK
        if (!m_session->SendPacket(std::string((char*) m_client_pk, crypto_box_PUBLICKEYBYTES)))
        {
            throw std::runtime_error("Bad handshake -> stopping");
        }

        // Receive server PK
        auto srvpkPkt = m_session->RecvPacket().value();
        memcpy(m_server_pk, srvpkPkt.data(), crypto_box_PUBLICKEYBYTES);

        // Receive encrypted group key
        auto grpPkt = m_session->RecvPacket().value();
        
        const unsigned char* nonce = (unsigned char*) grpPkt.data();
        const unsigned char* ct = nonce + crypto_box_NONCEBYTES;
        size_t ctLen = grpPkt.size() - crypto_box_NONCEBYTES;

        if (crypto_box_open_easy(
            m_group_key,
            ct,
            ctLen,
            nonce,
            m_server_pk,
            m_client_sk
        ) != 0)
        {
            throw std::runtime_error("Invalid group key -> stopping");
        }

        // Username

        if(!ChangeUsername())
        {
            throw std::runtime_error("Failed to set username. See logs for details.");
        }

        m_running = true;

    } catch (const std::exception& e)
    {
        m_exitReason = e.what();
        Debug::Log(std::string("Startup exception: ") + e.what(), Debug::LOG_LEVEL::ERROR);
        if (m_uiActive)
            m_ui.Cleanup();

        Stop(true);
        exit(1);

    }

    Debug::Log("Initializing threads...");

    // Threadhandling

    auto safe = [&](auto fn){
        return std::thread([this, fn](){
                try
                {
                    (this->*fn)();
                }
                catch (const std::exception& e)
                {
                    Debug::Log((std::string("Exception in thread: ") + e.what()).c_str());
                    Stop(true);
                }
                catch (...)
                {
                    Debug::Log("Unknown exception in thread, stopping");
                    Stop(true);
                }
            }
        );
    };

    m_threadPool.emplace_back(safe(&Client::HandleBroadcast));
    m_threadPool.emplace_back(safe(&Client::UIUpdateLoop));

    Debug::Log("Threads started");

    ClientLoop();

    Debug::Log("Joining threads...");

    int count{ 0 };
    for (auto &thr : m_threadPool)
    {
        if (thr.joinable())
        {
            thr.join();
            Debug::Log("==> Thread " + std::to_string(count) + " joined");
            count++;
        }
    }

    Debug::Log("Thread cleanup complete");

    m_ui.Cleanup();
    Debug::Log("UI cleanup complete");

    if (m_exitReason != "None")
    {
        Debug::Log("Client exited: " + m_exitReason, Debug::LOG_LEVEL::INFO);
        Debug::DumpToFile("log.txt");
        std::cout << "Exited: " << m_exitReason << '\n';
    }
}

void Client::Stop(bool)
{
    if (m_stopping)
    {
        return;
    }

    Debug::Log("Initiating shutdown");

    m_stopping = true;
    m_running = false;
    m_ui.running = false;
    m_uiActive = false;

    Debug::Log("Closing session...");
    CloseSession();
    Debug::Log("Session closed");
   
    Debug::Log("Clearing keys...");
    sodium_memzero(m_client_sk, sizeof m_client_sk);
    sodium_memzero(m_client_pk, sizeof m_client_pk);
    sodium_memzero(m_server_pk, sizeof m_server_pk);
    sodium_memzero(m_group_key, sizeof m_group_key);
    Debug::Log("Keys cleared");
}

bool Client::CreateSession()
{
    try
    {
        int fd{ socket(AF_INET, SOCK_STREAM, 0) };

        if (fd < 0)
        {
            throw std::runtime_error(std::string("Socket creation failed: ") + strerror(errno));
            return false;
        }

        // Connect to the server
        sockaddr_in addr{};

        addr.sin_family = AF_INET;
        addr.sin_port = htons(m_port);

        if (inet_pton(AF_INET, m_ip.c_str(), &addr.sin_addr) <= 0)
        {
            throw std::runtime_error("Invalid IP address" + m_ip);    
        }

        if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0)
        {
            throw std::runtime_error(std::string("Connect failed: ") + strerror(errno));
        }

        m_session = std::make_unique<NetworkSession>(fd);
        return true;
    }
    catch (const std::runtime_error& e)
    {
        Debug::Log(e.what());
        m_exitReason = e.what();
        return false;
    }
}

void Client::CloseSession()
{
    if (m_session)
        m_session->CloseSession();
}

bool Client::SendEncrypted(const std::string& plaintext)
{
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);

    std::vector<unsigned char> cipher(crypto_secretbox_MACBYTES + plaintext.size());
    
    if (crypto_secretbox_easy(
        cipher.data(),
        (unsigned char*) plaintext.data(),
        plaintext.size(),
        nonce,
        m_group_key
    ) != 0)
    {
        // Dropped
        return false;
    }

    std::string payload;
    payload.append((char*) nonce, crypto_secretbox_NONCEBYTES);
    payload.append((char*) cipher.data(), cipher.size());
    
    return m_session->SendPacket(payload);
}

std::optional<std::string> Client::RecvDecrypted()
{
    auto encOpt = m_session->RecvPacket();

    if (!encOpt)
        return std::nullopt;

    auto &enc{ *encOpt };

    if (enc.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
        return std::nullopt;

    const unsigned char* nonce{ (unsigned char*) enc.data() };
    const unsigned char* ct{ nonce + crypto_secretbox_NONCEBYTES };
    size_t ctLen{ enc.size() - crypto_secretbox_NONCEBYTES };
    size_t ptLen{ ctLen - crypto_secretbox_MACBYTES };

    std::vector<unsigned char> pt(ptLen);

    if (ctLen <= crypto_secretbox_MACBYTES)
    {
        Debug::Log("Encrypted message too short for valid decryption");
        return std::nullopt;
    }

    if (crypto_secretbox_open_easy(
        pt.data(),
        ct,
        ctLen,
        nonce,
        m_group_key
    ) != 0)
    {
        Debug::Log("Decryption failed: invalid ciphertext or tampering");
        return std::nullopt;
    }

    return std::string((char*) pt.data(), pt.size());
}

void Client::ClientLoop()
{
   const std::string prompt{ " > " };

   while (m_running)
   {
        auto inputOpt = m_ui.PromptInput(m_username + prompt);

        if (!inputOpt.has_value())
            break;

        std::string input{ inputOpt.value() };
        if (input.empty())
            continue;

        if (input == "/exit")
        {
            break;
        }

        SendEncrypted(m_username + ": " + input);
   }

   Stop();
}

void Client::UIUpdateLoop()
{
    while (m_running)
    {
        m_ui.PrintBufferedMessages();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    Stop();
}

void Client::HandleBroadcast()
{
    while (m_running)
    {
        auto msgOpt{ RecvDecrypted() };
        if (!msgOpt.has_value())
        {
            if (!m_stopping)
            {
                m_exitReason = "Server closed connection.";
                Debug::Log("Server closed the connection");
            }
            break;
        }

        const auto& msg{ *msgOpt };

        m_ui.PushMessage(msg);
    }

    Stop();
}
