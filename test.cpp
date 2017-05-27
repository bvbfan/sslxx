
#include <thread>
#include <iostream>

#include "sslxx.h"

const std::string text = "Hello, server :)";

class client : public sslxx::connector {
public:
    client(const char *addr, int port) : sslxx::connector(addr, port) {}
    void start() {
        while (true) {
            if (auto stream = connect()) {
                stream->send(text);
                break;
            }
            std::this_thread::yield();
        }
    }
};

class server : public sslxx::listener {
public:
    server(int port) : sslxx::listener(port, "server.pem") {}
    void start() {
        while (true) {
            if (auto stream = accept()) {
                std::cout << (stream->receive() == text ? "OK" : "FAIL") << '\n';
                break;
            }
        }
    }
};

int main(int argc, char *argv[])
{
    try {
        std::thread worker([]() {
            try {
                client("127.0.0.1", 8080).start();
            } catch(const std::exception &e) {
                std::cout << "client exception: " << e.what() << '\n';
                exit(1);
            }
        });
        server server(8080);
        server.start();
        worker.join();
    } catch(const std::exception &e) {
        std::cout << "server exception: " << e.what() << '\n';
        exit(1);
    }
    return 0;
}
