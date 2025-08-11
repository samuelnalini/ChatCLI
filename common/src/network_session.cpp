#include "../headers/network_session.hpp"

#include <arpa/inet.h>
#include <cstdint>
#include <optional>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/uio.h>
#include <vector>

NetworkSession::NetworkSession(int socketfd)
    : m_socketfd(socketfd)
{}

NetworkSession::~NetworkSession() = default;

bool NetworkSession::SendPacket(const std::string& data)
{
    if (m_socketfd < 0)
        return false;

    uint32_t len = static_cast<uint32_t>(data.size());
    uint32_t netLen = htonl(len);

    
    iovec iov[2];
    iov[0].iov_base = &netLen;
    iov[0].iov_len = PACKET_HEADER_SIZE;

    iov[1].iov_base = const_cast<char*>(data.data());
    iov[1].iov_len = len;

    size_t totalLen{ PACKET_HEADER_SIZE + len };
    size_t sent{ 0 };

    while (sent < totalLen)
    {
        ssize_t n = writev(m_socketfd, iov, 2);

        if (n < 0)
        {
            if (errno == EINTR)
                continue;

            return false;
        }

        sent += static_cast<size_t>(n);

        size_t remaining = n;

        for (int i{ 0 }; i < 2 && remaining > 0; ++i)
        {
            if (remaining >= iov[i].iov_len)
            {
                remaining -= iov[i].iov_len;
                iov[i].iov_base = static_cast<char*>(iov[i].iov_base) + iov[i].iov_len;
                iov[i].iov_len = 0;
            }
            else
            {
                iov[i].iov_base = static_cast<char*>(iov[i].iov_base) + remaining;
                iov[i].iov_len -= remaining;
                remaining = 0;
            }
        }
    }

    return true;
}



std::optional<std::string> NetworkSession::RecvPacket()
{

    if (m_socketfd < 0)
        return std::nullopt;

    uint32_t netLen{ 0 };
    ssize_t peeked = recv(m_socketfd, &netLen, PACKET_HEADER_SIZE, MSG_PEEK);

    if (peeked != PACKET_HEADER_SIZE)
        return std::nullopt;

    // Payload    
    uint32_t len = ntohl(netLen);

    if (len > MAX_PACKET_SIZE)
        return std::nullopt;

    std::vector<char> buffer(PACKET_HEADER_SIZE + len);
    
    ssize_t received = recv(m_socketfd, buffer.data(), buffer.size(), 0);

    if (received != static_cast<ssize_t>(buffer.size()))
        return std::nullopt;

    return std::string(buffer.begin() + PACKET_HEADER_SIZE, buffer.end());
}



void NetworkSession::CloseSession()
{
    if (m_socketfd >= 0)
    {
        shutdown(m_socketfd, SHUT_RDWR);
        close(m_socketfd);
        m_socketfd = -1;
    }
}
