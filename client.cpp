#include "udp_stream.hpp"
#include <csignal>
#include <iostream>
#include <cstring>

#define STREAM_CLIENT_NOP_DELAY 10000

udpstream::Client *client = nullptr;

void signalHandler(int sigNum)
{
    if ((client != nullptr) && client->IsEnabled()) {
        client->Disable();
    }
}

int main(int argc, char** argv)
{
    std::string address = "127.0.0.1";
    uint16_t port = UDP_STREAM_DEFAULT_PORT;

    if (argc > 1) { address = argv[1]; }
    if (argc > 2) { port = std::stoi(argv[2]); }

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTSTP, signalHandler);

    int result = EXIT_SUCCESS;

    try {
        client = new udpstream::Client(
            [&](uint16_t sampleRate, uint8_t channels, uint8_t bits, const uint8_t *data, std::size_t size) {
                std::cout << reinterpret_cast<const char *>(data) << std::endl;
            }, [&](const std::exception &exception) {
                std::cout << exception.what() << std::endl;
            });
        client->Enable(address, port);
        while (client->IsEnabled()) {
            std::this_thread::sleep_for(std::chrono::microseconds(STREAM_CLIENT_NOP_DELAY));
        }
    } catch (...) {
        result = EXIT_FAILURE;
    }

    if (client != nullptr) {
        auto temp = client;
        client = nullptr;
        delete temp;
    }
    return result;
}
