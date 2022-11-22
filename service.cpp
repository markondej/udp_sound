#include "udp_stream.hpp"
#include <iostream>
#include <csignal>
#include <cstring>

#define STREAM_SERVICE_NOP_DELAY 500000

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
    uint32_t samplingRate = UDP_STREAM_DEFAULT_SAMPLE_RATE;
    uint16_t port = UDP_STREAM_DEFAULT_PORT;
    uint8_t channels = UDP_STREAM_DEFAULT_CHANNELS, bitsPerChannel = UDP_STREAM_DEFAULT_BITS;
	std::atomic_bool useFir(false);

    if (argc > 1) { address = argv[1]; }
    if (argc > 2) { port = std::stoi(argv[2]); }
    if (argc > 3) { device = argv[3]; }
    if (argc > 4) { samplingRate = std::stoi(argv[4]); }
    if (argc > 5) { channels = std::stoi(argv[5]); }
    if (argc > 6) { bitsPerChannel = std::stoi(argv[6]); }
    if (argc > 7) { useFir = static_cast<bool>(std::stoi(argv[7])); }

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTSTP, signalHandler);

    int result = EXIT_SUCCESS;

    try {
        service = new udpstream::Service(
            [&](uint32_t samplingRate, uint8_t channels, uint8_t bitsPerChannel, uint8_t *data, std::size_t size) {
                return;
            }, [&](const std::exception &exception) {
                std::cout << exception.what() << std::endl;
            }, [&](const std::string &text) {
                std::cout << text << std::endl;
            });
        service->Enable(
            address,
            port,
            device,
            samplingRate,
            channels,
            bitsPerChannel
        );
        while (service->IsEnabled()) {
            std::this_thread::sleep_for(std::chrono::microseconds(STREAM_SERVICE_NOP_DELAY));
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
