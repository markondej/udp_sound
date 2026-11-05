#include "udp_stream.hpp"
#include <csignal>
#include <iostream>
#include <cstring>
#include <atomic>

#define STREAM_CLIENT_NOP_DELAY 500
#define BUFFERED_PLAYBACK_PRINT_INTERVAL 1000

std::atomic<bool> stop(false);

void signalHandler(int sigNum)
{
    stop.store(true);
}

int main(int argc, char** argv)
{
    std::string address = "127.0.0.1", device = UDP_STREAM_DEFAULT_OUTPUT_DEVICE;
    uint16_t port = UDP_STREAM_DEFAULT_PORT;

    if (argc > 1) { address = argv[1]; }
    if (argc > 2) { port = std::stoi(argv[2]); }
    if (argc > 3) { device = argv[3]; }

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    int result = EXIT_SUCCESS;

    try {
        std::atomic<uint32_t> rate(0);
        udpstream::OutputDevice output;
        udpstream::Client client(
            [&](uint32_t samplingRate, uint8_t channels, uint8_t bitsPerChannel, uint8_t *data, std::size_t size) {
                if (!output.IsEnabled()) {
                    std::cout << "Stream params: " << samplingRate << " Hz, " << static_cast<uint32_t>(channels) << " channel(s), " << static_cast<uint32_t>(bitsPerChannel) << " bits" << std::endl;
                    output.Enable(device, samplingRate, channels, bitsPerChannel);
                    rate.store(samplingRate);
                }
                output.SetData(data, size);
        }, [&](const std::exception &exception) {
                std::cerr << exception.what() << std::endl;
            });
        client.Enable(address, port);
        auto last = std::chrono::system_clock::now();
        while (!stop.load() && client.IsEnabled()) {
            std::string error = output.GetError();
            if (!error.empty()) {
                std::cerr << error <<std::endl;
                throw std::exception();
            } else {
                auto now = std::chrono::system_clock::now();
                auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(now - last).count();
                if ((diff > BUFFERED_PLAYBACK_PRINT_INTERVAL) && output.IsEnabled()) {
                    last = now;
                    std::cout << "\rBuffered playback: " << (output.GetBufferedSamples() * 1000 / rate.load()) << " ms" << std::flush;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(STREAM_CLIENT_NOP_DELAY));
            }
        }
        std::cout << std::endl;
    } catch (...) {
        result = EXIT_FAILURE;
    }

    return result;
}
