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
    std::string address = "127.0.0.1", device = UDP_STREAM_DEFAULT_OUTPUT_DEVICE;
    uint16_t port = UDP_STREAM_DEFAULT_PORT;

    if (argc > 1) { address = argv[1]; }
    if (argc > 2) { port = std::stoi(argv[2]); }
    if (argc > 3) { device = argv[3]; }

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTSTP, signalHandler);

    int result = EXIT_SUCCESS;

    udpstream::OutputDevice outputDevice;
    std::vector<uint8_t> outputData;
    struct SelectedParams {
        uint32_t samplingRate;
        uint8_t channels, bitsPerChannel;
    } *selected = nullptr;
    std::mutex access;

    try {
        client = new udpstream::Client(
            [&](uint32_t samplingRate, uint8_t channels, uint8_t bitsPerChannel, const uint8_t *data, std::size_t size) {
                std::lock_guard<std::mutex> lock(access);
                if (selected == nullptr) {
                    selected = new SelectedParams({ samplingRate, channels, bitsPerChannel });
                    std::cout << "Stream params: " << samplingRate << " Hz, " << static_cast<uint32_t>(channels) << " channel(s), " << static_cast<uint32_t>(bitsPerChannel) << " bits" << std::endl;
                }
                if ((selected->samplingRate == samplingRate) && (selected->channels == channels) && (selected->bitsPerChannel == bitsPerChannel)) {
                    std::size_t offset = outputData.size();
                    outputData.resize(offset + size);
                    std::memcpy(&outputData.data()[offset], data, size);
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
                std::lock_guard<std::mutex> lock(access);
                if (!outputDevice.IsEnabled() && selected != nullptr) {
                    outputDevice.SetData(outputData.data(), outputData.size());
                    outputDevice.Enable(device, selected->samplingRate, selected->channels, selected->bitsPerChannel);
                }
                if (!outputData.empty()) {
                    outputDevice.SetData(outputData.data(), outputData.size());
                    outputData.clear();
                }
            }
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
    if (selected != nullptr) {
        delete selected;
    }
    return result;
}
