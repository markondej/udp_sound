#include "udp_stream.hpp"
#include <iostream>
#include <csignal>
#include <cstring>
#include <atomic>

#define STREAM_SERVICE_NOP_DELAY 500

std::atomic<bool> stop(false);

void signalHandler(int sigNum)
{
    stop.store(true);
}

int main(int argc, char** argv)
{
    std::string address = UDP_STREAM_DEFAULT_ADDRESS, device = UDP_STREAM_DEFAULT_INPUT_DEVICE;
    uint32_t samplingRate = UDP_STREAM_DEFAULT_SAMPLE_RATE;
    uint16_t port = UDP_STREAM_DEFAULT_PORT;
    uint8_t channels = UDP_STREAM_DEFAULT_CHANNELS, bitsPerChannel = UDP_STREAM_DEFAULT_BITS;

    if (argc > 1) { address = argv[1]; }
    if (argc > 2) { port = std::stoi(argv[2]); }
    if (argc > 3) { device = argv[3]; }
    if (argc > 4) { samplingRate = std::stoi(argv[4]); }
    if (argc > 5) { channels = std::stoi(argv[5]); }
    if (argc > 6) { bitsPerChannel = std::stoi(argv[6]); }

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    int result = EXIT_SUCCESS;

    try {
        udpstream::Service service(
            [&](uint32_t samplingRate, uint8_t channels, uint8_t bitsPerChannel, uint8_t *data, std::size_t size) {
                return;
            }, [&](const std::exception &exception) {
                std::cerr << exception.what() << std::endl;
            }, [&](const std::string &text) {
                std::cout << text << std::endl;
            });
        service.Enable(
            address,
            port,
            device,
            samplingRate,
            channels,
            bitsPerChannel
        );
        while (!stop.load() && service.IsEnabled()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(STREAM_SERVICE_NOP_DELAY));
        }
    } catch (...) {
        result = EXIT_FAILURE;
    }

    return result;
}
