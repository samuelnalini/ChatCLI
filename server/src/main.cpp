#include "headers/server.hpp"

#include <string>
#include <iostream>

int main(int argc, char* argv[])
{

    uint16_t port{ 8080 };

    if (argc > 2)
    {
        std::cerr << "Usage: server <port = 8080>\n";
        return 1;
    }

    if (argc == 2)
    {
        int stoiInt = std::stoi(argv[1]);

        if (!stoiInt || stoiInt > 65535)
        {
            std::cerr << "Invalid port '" << argv[1] << "'\n";
            return 1;
        }
        
        port = stoiInt;
    }

    Server server(port);
    server.Start();
}
