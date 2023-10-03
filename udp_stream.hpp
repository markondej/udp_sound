#pragma once

#include <functional>
#include <string>
#include <vector>
#include <thread>
#include <atomic>

#define UDP_STREAM_DEFAULT_INPUT_DEVICE "default"
#define UDP_STREAM_DEFAULT_OUTPUT_DEVICE "default"

#define UDP_STREAM_DEFAULT_SAMPLE_RATE 44100
#define UDP_STREAM_DEFAULT_CHANNELS 2
#define UDP_STREAM_DEFAULT_BITS 16

#define UDP_STREAM_DEFAULT_ADDRESS "0.0.0.0"
#define UDP_STREAM_DEFAULT_PORT 8734

namespace udpstream {
    class Switchable {
    public:
        Switchable();
        bool IsEnabled() const;
        virtual bool Disable();
    protected:
        bool Enable();
        std::atomic_bool enabled;
    };

    using ExceptionHandler = std::function<void(const std::exception &exception)>;
    using LogHandler = std::function<void(const std::string &text)>;
    using DataHandler = std::function<void(uint32_t samplingRate, uint8_t channels, uint8_t bitsPerChannel, uint8_t *data, std::size_t size)>;

    class Service : public Switchable {
    public:
        Service(
            const DataHandler &dataHandler = nullptr,
            const ExceptionHandler &exceptionHandler = nullptr,
            const LogHandler &logHandler = nullptr
        );
        Service(const Service &) = delete;
        Service(Service &&) = delete;
        Service &operator=(const Service &) = delete;
        virtual ~Service();
        void Enable(
            const std::string &address = UDP_STREAM_DEFAULT_ADDRESS,
            uint16_t port = UDP_STREAM_DEFAULT_PORT,
            const std::string &device = UDP_STREAM_DEFAULT_INPUT_DEVICE,
            uint32_t samplingRate = UDP_STREAM_DEFAULT_SAMPLE_RATE,
            uint8_t channels = UDP_STREAM_DEFAULT_CHANNELS,
            uint8_t bitsPerChannel = UDP_STREAM_DEFAULT_BITS
        );
        bool Disable();
    private:
        static void ServiceThread(
            Service *instance,
            const std::string &address,
            uint16_t port,
            const std::string &device,
            uint32_t samplingRate,
            uint8_t channels,
            uint8_t bitsPerChannel,
            const DataHandler &dataHandler = nullptr,
            const ExceptionHandler &exceptionHandler = nullptr,
            const LogHandler &logHandler = nullptr
        );
        DataHandler dataHandler;
        ExceptionHandler exceptionHandler;
        LogHandler logHandler;
        std::thread thread;
    };

    class Client : public Switchable {
    public:
        Client(
            const DataHandler &dataHandler,
            const ExceptionHandler &exceptionHandler = nullptr
        );
        Client(const Client &) = delete;
        Client(Client &&) = delete;
        Client &operator=(const Client &) = delete;
        virtual ~Client();
        void Enable(const std::string &address, uint16_t port, const std::string &device = UDP_STREAM_DEFAULT_OUTPUT_DEVICE);
        bool Disable();
    private:
        static void ClientThread(
            Client *instance,
            const std::string &address,
            uint16_t port,
            const std::string &device,
            const DataHandler &dataHandler = nullptr,
            const ExceptionHandler &exceptionHandler = nullptr
        );
        DataHandler dataHandler;
        ExceptionHandler exceptionHandler;
        std::thread thread;
    };

    class OutputDevice : public Switchable {
    public:
        OutputDevice();
        OutputDevice(const OutputDevice &) = delete;
        OutputDevice(OutputDevice &&) = delete;
        virtual ~OutputDevice();
        OutputDevice &operator=(const OutputDevice &) = delete;
        void Enable(const std::string &device, uint32_t samplingRate, uint8_t channels, uint8_t bitsPerChannel);
        bool Disable();
        std::string GetError();
        void SetData(const uint8_t *data, std::size_t size);
        std::size_t GetBufferedSamples() const;
    private:
        static void DeviceThread(OutputDevice *instance, const std::string &device, uint32_t samplingRate, uint8_t channels, uint8_t bitsPerChannel);
        std::atomic<std::vector<uint8_t> *> data;
        std::atomic<std::string *> error;
        std::atomic_size_t buffered;
        std::thread thread;
    };
}
