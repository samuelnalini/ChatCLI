#include "headers/client.hpp"

#include <string>
#include <iostream>
#include <regex>

Client* clientPtr;

[[nodiscard]]
inline std::optional<uint16_t> checkPort(const std::string& portStr)
{
    const uint16_t stoiPort = std::stoi(portStr);

    if (!stoiPort)
    {
        return std::nullopt;
    }

    if (stoiPort > 65535)
    {
        return std::nullopt;
    }

    return stoiPort;
}

[[nodiscard]]
inline std::optional<std::string> checkIP(const std::string& ipStr)
{
    std::regex ipv4("(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])");

    if (!std::regex_match(ipStr, ipv4))
        return std::nullopt;

    return ipStr;
}

bool setArgs(const std::vector<std::string>& args, uint16_t& port, std::string& ip)
{
    for (int i{1}; i < args.size(); i++)
    {

        if (args[i].at(0) != '-')
        {
             // Assume ip
            auto ipCheck = checkIP(args[i]);

            if (!ipCheck.has_value())
            {
                std::cerr << "Invalid IP \"" << args[i] << "\"\n";
                return false;
            }

            ip = ipCheck.value();
            continue;
        }

        if (args.size() < (i + 1))
        {
            std::cerr << "Usage: client -i/--ip <ipv4> -p/--port <num>\n";
            return false;
        }

        if (args[i] == "-p" || args[i] == "--port")
        {
            const std::optional<uint16_t> portCheck = checkPort(args[i + 1]);

            if (!portCheck.has_value())
            {
                std::cerr << "Invalid port \"" << args[i + 1] << "\"\n";
                return false;
            }

            port = portCheck.value();
            i++;
            continue;
        }
        
        if (args[i] == "-i" || args[i] == "--ip")
        {
            const std::optional<std::string> ipCheck = checkIP(args[i + 1]);

            if (!ipCheck.has_value())
            {
                std::cerr << "Invalid IP \"" << args[i + 1] << "\"\n";
                return false;
            }

            ip = ipCheck.value();
        }
    }

    return true;
}

int main(int argc, const char* argv[])
{
    uint16_t port{ 8080 };
    std::string ip{ "127.0.0.1" };

    std::vector<std::string> args;
    args.assign(argv, argv + argc);

    setArgs(args, port, ip);

    Client client(ip, port);
    client.Start();
}
