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


[[deprecated("See SendPacket()")]]
static inline ssize_t send_all(int fd, char* buf, size_t bufSize, int flags)
{
    size_t totalSent{ 0 };
    
    while (totalSent < bufSize)
    {
        ssize_t sent = send(fd, buf + totalSent, (bufSize - totalSent), flags);

        if (sent < 0)
        {
            if (errno == EINTR)
                continue;

            return -1;
        }

        if (sent == 0)
        {
            // Peer closed the connection
            return totalSent;
        }

        totalSent += static_cast<size_t>(sent);
    }

    return static_cast<size_t>(totalSent);
}

[[deprecated("See RecvPacket()")]]
static inline ssize_t recv_all(int fd, char* buf, size_t bufSize, int flags)
{
    size_t totalRecv{ 0 };

    while (totalRecv < bufSize)
    {
        ssize_t recvd = recv(fd, (buf + totalRecv), (bufSize - totalRecv), flags);

        if (recvd < 0)
        {
            if (errno == EINTR)
                continue;

            return -1;
        }

        if (recvd == 0)
        {
            // Peer closed the connection
            return totalRecv;
        }

        totalRecv += static_cast<size_t>(recvd);
    }

    return static_cast<ssize_t>(totalRecv);
}
