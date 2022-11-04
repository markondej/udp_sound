#include "udp_stream.hpp"
#include <csignal>
#include <iostream>
#include <cstring>

#define STREAM_CLIENT_NOP_DELAY 1000

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

    udpstream::OutputDevice outputDevice;
    std::atomic<std::vector<uint8_t> *> outputStream;
    struct SelectedParams {
        uint32_t samplingRate;
        uint8_t channels, bitsPerChannel;
    };
    std::atomic<SelectedParams *> selected;

    try {
        client = new udpstream::Client(
            [&](uint32_t samplingRate, uint8_t channels, uint8_t bitsPerChannel, uint8_t *data, std::size_t size) {
                SelectedParams *params = new SelectedParams({ samplingRate, channels, bitsPerChannel }), *required = nullptr;
                if (!selected.compare_exchange_strong(required, params)) {
                    delete params;
                } else {
                    std::cout << "Stream params: " << samplingRate << " Hz, " << static_cast<uint32_t>(channels) << " channel(s), " << static_cast<uint32_t>(bitsPerChannel) << " bits" << std::endl;
                }
                params = selected.load();
                if ((params->samplingRate == samplingRate) && (params->channels == channels) && (params->bitsPerChannel == bitsPerChannel)) {
                    std::vector<uint8_t> *previous, *stream = new std::vector<uint8_t>();
                    stream->resize(size);
                    std::memcpy(stream->data(), data, size);
                    previous = outputStream.exchange(stream);
                    if (previous != nullptr) {
                        delete previous;
                        std::cout << "Warning: overrun detected" << std::endl;
                    }
                }
            }, [&](const std::exception &exception) {
                std::cout << exception.what() << std::endl;
            });
        client->Enable(address, port);
        while (client->IsEnabled()) {
            std::string error = outputDevice.GetError();
            if (!error.empty()) {
                throw std::runtime_error(error.c_str());
            } else {
                std::vector<uint8_t> *stream = outputStream.exchange(nullptr);
                if (stream != nullptr) {
                    try {
                        outputDevice.SetData(stream->data(), stream->size());
                    } catch (...) { } 
                    delete stream;
                    if (!outputDevice.IsEnabled()) {
                        SelectedParams *params = selected.load(std::memory_order_consume);
                        outputDevice.Enable(device, params->samplingRate, params->channels, params->bitsPerChannel);
                    }
                } else {
                    std::this_thread::sleep_for(std::chrono::microseconds(STREAM_CLIENT_NOP_DELAY));
                }
            }
        }
    } catch (...) {
        result = EXIT_FAILURE;
    }

    if (client != nullptr) {
        auto temp = client;
        client = nullptr;
        delete temp;
    }

    SelectedParams *params = selected.load(std::memory_order_consume);
    if (params != nullptr) {
        delete params;
    }

    std::vector<uint8_t> *stream = outputStream.exchange(nullptr);
    if (stream != nullptr) {
        delete stream;
    }

    return result;
}
