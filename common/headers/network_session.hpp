#pragma once

#include <string>
#include <optional>
#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>

constexpr size_t PACKET_HEADER_SIZE = sizeof(uint32_t);
constexpr size_t MAX_PACKET_SIZE = 64 * 1024; // 64 KiB

class NetworkSession
{
public:
    explicit NetworkSession(int socketfd);
    ~NetworkSession();

    NetworkSession(const NetworkSession&) = delete;
    NetworkSession& operator = (const NetworkSession&) = delete;

    [[nodiscard]]
    bool SendPacket(const std::string& data);

    [[nodiscard]]
    std::optional<std::string> RecvPacket();

    void CloseSession();
private:
    int m_socketfd;
};
