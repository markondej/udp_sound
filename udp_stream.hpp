#pragma once

#include <functional>
#include <thread>
#include <atomic>
#include <mutex>

#define UDP_STREAM_DEFAULT_INPUT_DEVICE ""
#define UDP_STREAM_DEFAULT_OUTPUT_DEVICE ""

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
        void Disable() noexcept;
    protected:
        std::atomic_bool enabled;
    };

    using ExceptionHandler = std::function<void(const std::exception &exception) noexcept>;
    using LogHandler = std::function<void(const std::string &text) noexcept>;

    class Service : public Switchable {
    public:
        Service(
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
            uint16_t sampleRate = UDP_STREAM_DEFAULT_SAMPLE_RATE,
            uint8_t channels = UDP_STREAM_DEFAULT_CHANNELS,
            uint8_t bits = UDP_STREAM_DEFAULT_BITS
        );
        void Disable() noexcept;
    private:
        static void ServiceThread(
            Service *instance,
            const std::string &address,
            uint16_t port,
            const std::string &device,
            uint16_t sampleRate,
            uint8_t channels,
            uint8_t bits
        ) noexcept;
        ExceptionHandler exceptionHandler;
        LogHandler logHandler;
        std::thread thread;
        std::mutex access;
    };

    class Client : public Switchable {
    public:
        using DataHandler = std::function<void(uint16_t sampleRate, uint8_t channels, uint8_t bits, const uint8_t *data, std::size_t size) noexcept>;
        Client(
            const DataHandler &dataHandler,
            const ExceptionHandler &exceptionHandler = nullptr
        );
        Client(const Client &) = delete;
        Client(Client &&) = delete;
        Client &operator=(const Client &) = delete;
        virtual ~Client();
        void Enable(const std::string &address, uint16_t port, const std::string &device = UDP_STREAM_DEFAULT_OUTPUT_DEVICE);
        void Disable() noexcept;
    private:
        static void ClientThread(
            Client *instance,
            const std::string &address,
            uint16_t port,
            const std::string &device
        ) noexcept;
        DataHandler dataHandler;
        ExceptionHandler exceptionHandler;
        std::thread thread;
        std::mutex access;
    };
}
