# CLIChat
*Encrypted group chats directly from your commandline!*

## ABOUT:

CLIChat is a command line app that allows users to create and join encrypted group chats. Written in C++, its lightweight design makes it ideal for communication. By making use of the ncurses UI library, it provides a simple to use user interface, right in your terminal! Furthermore; the use of modern concepts allow for quick run times, while the libsodium library ensures secure encryption for *all* communication.

<sub>*Please see [CONSIDERATIONS](#considerations)*</sub>

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
cd CLIChat && mkdir -p build && cd build
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

(chat-app/build) `./client <ip> <port>` (must specify both and in this order)

It will prompt the user to pick a username and then join the chat.

## CLIENT COMMANDS

The client is able to send special commands to the server by prefixing them with `/`

`/exit` - disconnects the client gracefully

## CONSIDERATIONS:

*NOTE: There is no safety guarantee for this program. Though messages SHOULD be encrypted, no system is ever 100% secure. I am still working on this and updating it, but I am not liable for anything that may occur as a result of using this application. Use this at your own risk.*

*NOTE: This was designed to run on Linux machines! The socket code for other platforms are slightly different and will not work without modification!*

#### THINGS I'VE LEARNED THROUGH THIS PROJECT:
  - User input
  - CMake Build Tools
  - Package management through vcpkg
  - Message encryption through libsodium
  - Networking through sockets and packets
  - TCP Socket Implementation
  - Basic Client/Server Architecture
  - The use of threads, multithreading and thread safety
  - epoll() and event-based systems.
  - Debugging skills
  - Development in Linux
  - Error handling through the use of try/catch blocks, exception handling
