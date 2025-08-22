# ChatCLI
*Encrypted group chats directly from your commandline!*

## ABOUT:

ChatCLI is a command line app that allows users to create and join encrypted group chats. Written in C++, its lightweight design makes it ideal for communication. By making use of the ncurses UI library, it provides a simple to use user interface, right in your terminal! Furthermore; the use of modern concepts allow for quick run times, while the libsodium library ensures secure encryption for *all* communication.

<sub>*Please see [CONSIDERATIONS](#considerations) before attempting to use this*</sub>

## HELP SECTION:

When you first download the project, you'll notice that it's split up into two separate binaries.

The **server** is responsible for accepting user connections, forwarding messages to other clients, and ensuring things like unique usernames.

The **client** is what most users see and interact with. It allows users to connect to a server, provides the user interface, and displays messages.

You can look through these sections to help you get started:

- *[build instructions](#build-instructions) - how to download the project*
- *[dependencies](#dependencies) - requirements to run the project*
- *[server instructions](#server-instructions) - how to run the server*
- *[client instructions](#client-instructions) - how to run the client*
- *[client commands](#client-commands) - client command list*

## DEPENDENCIES

Before anything, you should be sure that you have the required dependencies, otherwise the project will **not build**

Firstly, update your machine (Ubuntu example):

```
sudo apt update
```

```
sudo apt upgrade
```

You can then move on to installing the required packages. This is an example for Ubuntu, but similar packages are available on other distros as well:

```
sudo apt install build-essential cmake curl git unzip pkg-config autoconf automake libtool zip libncurses-dev libsodium-dev
```

## BUILD INSTRUCTIONS

Once you have the required [dependencies](#dependencies), you can move on to downloading and building the project.

First, clone the repo wherever you'd like:

```
git clone --recurse-submodules -j8 https://github.com/samuelnalini/cli-chat-app.git
```

Create a build directory:

```
cd ChatCLI && mkdir -p build && cd build
```

Continuing in our `build/`, run cmake:

```
cmake -G "Unix Makefiles" ..
```

And lastly, still in `build/`:

```
make
```

*If you're having problems, be 100% sure that you have **everything** done in the [DEPENDENCIES](#dependencies) section.*

## SERVER INSTRUCTIONS

You can start the server simply by running it as an executable:

(chat-app/build) `./server`

This will start the server on port `8080` by default

or, if you'd like to specify a port you can run:

(chat-app/build) `./server <port>`

The server will then initialize and begin listening on the specified port.

## CLIENT INSTRUCTIONS

The client is very similar to the server, but must specify an IP and port in order to communicate with a server.

**Since the client relies on a server to function, it must connect directly to one on startup**

You can run the client as an executable:

(chat-app/build) `./client`

This will start the client on `127.0.0.1` on port `8080`

or if you'd like to specify an IP and port:

(chat-app/build) `./client -i/--ip <ip> -p/--port <port>`

You can specify one or the other, if you don't it'll use the aforementioned defaults

## CLIENT COMMANDS

The client is able to send special commands to the server by prefixing them with `/`

`/exit` - disconnects the client gracefully

## ERROR HANDLING

Being network dependent, it is very possible that you will encounter errors while using ChatCLI. A robust error handling system allows for detailed error messages and exception recovery.

<sub>If you notice that something breaks often, you should open up an issue.</sub>

> [!NOTE]
> When opening up an issue, be sure to include the entire log info for that specific session, as well as any other important context.

### SERVER ERRORS

Server errors are easy to spot, if something fails it will be displayed directly on the terminal. If it is a critical error and the program must exit, a `server.log` file will be generated in the same directory as the binary.
If nothing is generating, consider the possibility of permission errors. The program might not have permissions to create/write to files.

When viewing the contents of server.log, you will notice detailed logs about what the server is doing in the background. You can easily `cat server.log | grep ERROR` to see exactly where each error occurred, the error message, a timestamp.

### CLIENT ERRORS

Client errors are not as easy as the server because there is no direct message displayed on the screen. Client logs will all be placed in `client.log`, making binary permissions essential for file writing/editing. Like the server, error logs will generate in the same directory as the binary.

The contents of client.log are similar to those of the server's log. It will contain info about client startup and background tasks. Once again `cat client.log | grep ERROR` will show you exactly where errors occurred, why, and when.

## CONSIDERATIONS:

> [!CAUTION]
> There is no safety guarantee for this program. Though messages are encrypted, no system is ever 100% secure. I am *not an expert in cybersecurity* and I am not liable for anything that may occur as a result of using this application. Use this at your own risk.*

> [!NOTE]
> This was designed to run on Linux machines! The socket code for other platforms are slightly different and will not work without modification!*

> [!NOTE]
> Contributions are encouraged and extremely appreciated!

> [!WARNING]
> Bug reports are necessary, encouraged and appreciated! However,<br>
> You should look at [ERROR HANDLING](#error-handling) before opening up an issue

> #### THINGS I'VE LEARNED THROUGH THIS PROJECT:
>  - User input
>  - CMake Build Tools
>  - Package management through vcpkg
>  - Message encryption through libsodium
>  - Networking through sockets and packets
>  - TCP Socket Implementation
>  - Basic Client/Server Architecture
>  - The use of threads, multithreading and thread safety
>  - epoll() and event-based systems.
>  - Debugging skills
>  - Development in Linux
>  - Error handling through the use of try/catch blocks, exception handling
>  - Some regex magic
 
As of right now, the plan is to recreate this application in C, which will allow for greater control.
