#include "udp_stream.hpp"
#include <iostream>
#include <csignal>

#define CONSOLE_NOP_DELAY 500000

udpstream::Service *service = nullptr;

void signalHandler(int sigNum)
{
    if ((service != nullptr) && service->IsEnabled()) {
        service->Disable();
    }
}
int main(int argc, char** argv)
{
    std::string address = UDP_STREAM_DEFAULT_ADDRESS, device = UDP_STREAM_DEFAULT_INPUT_DEVICE;
    uint16_t port = UDP_STREAM_DEFAULT_PORT, sampleRate = UDP_STREAM_DEFAULT_SAMPLE_RATE;
    uint8_t channels = UDP_STREAM_DEFAULT_CHANNELS, bits = UDP_STREAM_DEFAULT_BITS;

    if (argc > 1) { address = argv[1]; }
    if (argc > 2) { port = std::stoi(argv[2]); }
    if (argc > 3) { device = argv[3]; }
    if (argc > 4) { sampleRate = std::stoi(argv[4]); }
    if (argc > 5) { channels = std::stoi(argv[5]); }
    if (argc > 6) { bits = std::stoi(argv[6]); }

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTSTP, signalHandler);

    int result = EXIT_SUCCESS;

    try {
        service = new udpstream::Service(
            [&](const std::exception &exception) {
                std::cout << exception.what() << std::endl;
            }, [&](const std::string &text) {
                std::cout << text << std::endl;
            });
        service->Enable(
            address,
            port,
            device,
            sampleRate,
            channels,
            bits
        );
        while (service->IsEnabled()) {
            std::this_thread::sleep_for(std::chrono::microseconds(CONSOLE_NOP_DELAY));
        }
    } catch (...) {
        result = EXIT_FAILURE;
    }

    if (service != nullptr) {
        auto temp = service;
        service = nullptr;
        delete temp;
    }
    return result;
}
