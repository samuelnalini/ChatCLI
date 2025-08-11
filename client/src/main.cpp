#include "headers/client.hpp"

#include <string>
#include <iostream>
#include <regex>

Client* clientPtr;

const std::vector<std::string> parseArgs(int argc, const char* argv[])
{
    std::vector<std::string> args;
    
    for (int i = 1; i < argc; i++)
    {
        args.push_back(argv[i]);
    }

    return args;
}

inline std::optional<uint16_t> checkPort(std::string& portStr)
{
    auto stoiPort = std::stoi(portStr);

    if (!stoiPort)
    {
        return std::nullopt;
    }

    if (stoiPort > 65535 || stoiPort <= 0)
    {
        return std::nullopt;
    }

    return stoiPort;
}

inline std::optional<std::string> checkIP(std::string& ipStr)
{
    std::regex ipv4("(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])");

    if (!std::regex_match(ipStr, ipv4))
        return std::nullopt;

    return ipStr;
}

bool setArgs(std::vector<std::string>& args, uint16_t& port, std::string& ip)
{
    for (int i{ 0 }; i < args.size(); i++)
    {
        if (args[i] == "-p" || args[i] == "--port")
        {
            if (args.size() < (i + 1))
            {
                std::cerr << "Usage: -p/--port <num>\n";
                return false;
            }

            auto portCheck = checkPort(args[i + 1]);

            if (!portCheck.has_value())
            {
                std::cerr << "Invalid port \"" << args[i + 1] << "\"\n";
                return false;
            }

            port = portCheck.value();
            i++;
        }
        else if (args[i] == "-i" || args[i] == "--ip")
        {
            if (args.size() < (i + 1))
            {
                std::cerr << "Usage: -i/--ip <num>\n";
                return false;
            }

            auto ipCheck = checkIP(args[i + 1]);

            if (!ipCheck.has_value())
            {
                std::cerr << "Invalid IP \"" << args[i + 1] << "\"\n";
                return false;
            }

            ip = ipCheck.value();
        }
        else
        {
            // Assume ip
            auto ipCheck = checkIP(args[i]);

            if (!ipCheck.has_value())
            {
                std::cerr << "Invalid IP \"" << args[i] << "\"\n";
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

    std::vector<std::string> args = parseArgs(argc, argv); // convert argv into a vector, probably should optimize later

    setArgs(args, port, ip);

    Client client(ip, port);
    client.Start();
}
