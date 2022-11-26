#include "udp_stream.hpp"
#include <csignal>
#include <iostream>
#include <cstring>

#define STREAM_CLIENT_NOP_DELAY 1000
#define BUFFERED_PLAYBACK_PRINT_INTERVAL 1000

udpstream::Client *client = nullptr;

void signalHandler(int sigNum)
{
    if ((client != nullptr) && client->IsEnabled()) {
        client->Disable();
    }
}

int main(int argc, char** argv)
{
    std::string address = "127.0.0.1", device = UDP_STREAM_DEFAULT_OUTPUT_DEVICE;
    uint16_t port = UDP_STREAM_DEFAULT_PORT;

    if (argc > 1) { address = argv[1]; }
    if (argc > 2) { port = std::stoi(argv[2]); }
    if (argc > 3) { device = argv[3]; }

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTSTP, signalHandler);

    int result = EXIT_SUCCESS;

    udpstream::OutputDevice output;
    std::atomic<uint32_t> rate(0);

    try {
        client = new udpstream::Client(
            [&](uint32_t samplingRate, uint8_t channels, uint8_t bitsPerChannel, uint8_t *data, std::size_t size) {
                if (!output.IsEnabled()) {
                    std::cout << "Stream params: " << samplingRate << " Hz, " << static_cast<uint32_t>(channels) << " channel(s), " << static_cast<uint32_t>(bitsPerChannel) << " bits" << std::endl;
                    output.Enable(device, samplingRate, channels, bitsPerChannel);
                    rate = samplingRate;
                }
                output.SetData(data, size);

        }, [&](const std::exception &exception) {
                std::cout << exception.what() << std::endl;
            });
        client->Enable(address, port);
        auto last = std::chrono::system_clock::now();
        while (client->IsEnabled()) {
            std::string error = output.GetError();
            if (!error.empty()) {
                throw std::runtime_error(error.c_str());
            } else {
                auto now = std::chrono::system_clock::now();
                auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(now - last).count();
                if ((diff > BUFFERED_PLAYBACK_PRINT_INTERVAL) && output.IsEnabled()) {
                    last = now;
                    std::cout << "\rBuffered playback: " << (output.GetBufferedSamples() * 1000 / rate.load()) << " ms" << std::flush;
                }
                std::this_thread::sleep_for(std::chrono::microseconds(STREAM_CLIENT_NOP_DELAY));
            }
        }
        std::cout << std::endl;
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
