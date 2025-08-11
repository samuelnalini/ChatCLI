# 0.4.3a - Refactor continued
    OPTIMIZATIONS
    [-] SendPacket and RecvPacket rewritten to use iov instead of strings, reducing the amount of copies
    [-] SendPacket will now only send one packet instead of two per message, improving efficiency

    CHANGES & QUALITY OF LIFE
    [-] Deprecated send_all (see SendPacket)
    [-] Deprecated recv_all (see RecvPacket)
    [-] nodiscard attribute set for SendPacket and RecvPacket
    [-] Further improved error handling to rely more on exceptions
    [-] Improved logs
    [-] The server will now properly memzero all stored keys
    [-] The client will now properly memzero all stored keys
    [-] Went through and made some things more readable for maintainability

    BUG FIXES
    [-] /exit will now properly exit on the client
    [-] The server will now properly continue on a failed event instead of closing out entirely

# 0.4.3 - Minor refactor
    CHANGES
    [-] Invalid usernames will no longer exit the program
    [-] Improved debug logging
    [-] Improved error handling with the use of runtime_error
    [-] Implemented a retry loop if messages fail to send, will disconnect on the third failed attempt (out of sync error)

# 0.4.2 - Optimization & readability
    CHANGES
    [-] Const correctness in the server's use of ports
    [-] The server now relies more on ClientInfo than the raw file descriptors

# 0.4.1 - Bug fixes & Input improvements

    BUG FIXES
    [-] The server was not responding to SIGINT appropriately
    [-] The client would seg fault upon the server closing the connection
    [-] The client was not responding to /exit appropriately
    [-] The UI was not closing upon client exit

    IMPROVEMENTS
    [+] You can now scroll through text with the arrow keys
    [+] Added support for home and end keys
    [+] Ignored up and down arrow keys that were inserting characters
    [+] The debugger has been reworked
    [+] log.txt and server_log.txt will now only generate if an error occurred
    [+] Debug logs will now display a timestamp and a log level (INFO, WARNING, ERROR)

# 0.4.0 - Message encryption!
    ADDITIONS
    [+] Usernames are now encrypted
    [+] Messages are now encrypted

    Each session generates a unique key that is then shared with the clients connected.

# 0.3.5 - UTF-8 & terminal colors
    ADDITIONS
    [+] UTF-8 submodule
    [+] UTF-8 compatibility
    [+] Style class that allows for styled server output

    MISC
    [-] Input optimizations
    [-] The server module is now more verbose
    [-] Added startup tests
    [-] The server module now displays terminal colors

# 0.3.4 - Server updates
    CHANGES
    [-] The server now uses epoll() instead of threads
    [-] Switched the server to an event based system.
    [-] Refactored parts of the server for efficiency

    MISC
    [-] The server no longer takes in an IP as an argument
        - Instead, you should only specify `./server <port = 8080>`
    [-] Updated the usage to reflect changes
    [-] Updated README.md to reflect changes

# 0.3.3 - Network optimization
    REMOVED
    [-] common.cpp became redundant after network_session was added
    
    MISC
    [-] Network packets sent have been reduced by half!
    [-] Switched port from int to uint16_t

# 0.3.2 - Stability improvements
    MISC
    [-] Improved code readability
    [-] Improved error handling
    [-] Debugger overloaded functions for boolean logging
    [-] Debugger improved performance
    [-] Improved thread safety
    [-] Further checks to prevent memory leaks
    [-] Improved user input stability
    [-] Minor refactors

# 0.3.1 - Debugger update
    ADDITIONS
    [+] Added a debugger class to allow for more robust logging

    BUG FIXES
    [-] Segmentation fault on exit has been fixed (again)
    [-] Fixed all known bugs

    MISC
    [-] Stability improvements

# 0.3.0 - Refactor and expansion
    ADDITIONS
    [+] vcpkg package manager
    [+] libsodium for future message encryption
    [+] Reintroduced seg fault on exit (TODO lol)

    BUG FIXES
    [-] Fixed a bug with ncurses window refreshing
    
    MISC
    [-] Added common/headers and common/src for consistency
    [-] Added network_session as a network wrapper
    [-] Added documentation in certain files (WIP)
    [-] Switched remaining class function names to CamelCase for consistency
    [-] Renamed remaining member variables to reflect the 'm_varName' style
    [-] Refactored server code to reflect the new NetworkSession class.
    [-] Implemented unique_ptr for improved memory management
    [-] server/HandleClient was replaced with HandleClientSession

# 0.2.1 - Hotfix
    BUG FIXES
    [-] Fixed segmentation fault on /exit
    [-] Fixed all known bugs
    [-] Stability improvements

# 0.2.0 - UI is here!

    ADDITIONS
    [+] Added ncurses UI!
    [+] Input is no longer linked to message updates
    [+] Input is now in a separate window from the message screen

    BUG FIXES
    [-] Many problems with socket creation and closing
    [-] Sockets now shutdown instead of closing abruptly

    MISC
    [-] More descriptive errors
    [-] Stability improvements
    [-] The server now supports up to 10 clients instead of 5. That's a 100% increase!

    KNOWN ISSUES
    [-] Seg fault when /exit is run (the program still exits, just in a crash and burn kind of way instead of a graceful bird gently landing on a branch)

# 0.1.1

    CHANGES
    [-] You can now specify the IP and port when launching the server and/or client
    [-] Updated the README to reflect these changes

# 0.1.0 - Initial release

    ADDITIONS
    [+] A server that can handle client connections
    [+] A client that can connect to a server
