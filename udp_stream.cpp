#include "udp_stream.hpp"
#include <regex>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#define ALSA_PCM_NEW_HW_PARAMS_API
#include <alsa/asoundlib.h>

#ifndef UDP_SERVER_PACKET_LENGTH
#define UDP_SERVER_PACKET_LENGTH 32 * 1024
#endif

#define UDP_SERVER_NOP_DELAY 1000

#define UDP_STREAM_REGISTER_TIMEOUT 5
#define UDP_STREAM_NOP_DELAY 1000
#define UDP_STREAM_PERIOD_SIZE 4000
#define UDP_STREAM_BUFFER_TIME 500000

#define UDP_STREAM_CLIENT_REQUEST_REGISTER 0x01
#define UDP_STREAM_CLIENT_REQUEST_UNREGISTER 0x02

namespace udpstream {
    class IPAddress {
    public:
        enum class Type {
            IPv4,
            IPv6,
            Unknown
        };
        IPAddress() {
            address = reinterpret_cast<sockaddr *>(new sockaddr_in);
            std::memset(address, 0, sizeof(sockaddr_in));
            (reinterpret_cast<sockaddr_in *>(address))->sin_family = AF_INET;
        }
        IPAddress(const std::string &address, Type type = Type::Unknown) {
            auto init = [&](Type type) {
                switch (type) {
                case Type::IPv6:
                    this->address = reinterpret_cast<sockaddr *>(new sockaddr_in6);
                    std::memset(this->address, 0, sizeof(sockaddr_in6));
                    (reinterpret_cast<sockaddr_in6 *>(this->address))->sin6_family = AF_INET6;
                    if (inet_pton(AF_INET6, address.c_str(), &(reinterpret_cast<sockaddr_in6 *>(this->address))->sin6_addr) <= 0) {
                        delete this->address;
                        throw std::runtime_error("Incorrect IPv6 address provided");
                    }
                    break;
                case Type::IPv4:
                default:
                    this->address = reinterpret_cast<sockaddr *>(new sockaddr_in);
                    std::memset(this->address, 0, sizeof(sockaddr_in));
                    (reinterpret_cast<sockaddr_in *>(this->address))->sin_family = AF_INET;
                    if (inet_pton(AF_INET, address.c_str(), &(reinterpret_cast<sockaddr_in *>(this->address))->sin_addr) <= 0) {
                        delete this->address;
                        throw std::runtime_error("Incorrect IPv4 address provided");
                    }
                }
            };
            bool resolve = true;
            if ((type != Type::Unknown) && IsCorrect(address, type)) {
                init(type);
                resolve = false;
            }
            else if (type == Type::Unknown) {
                if (IsCorrect(address, Type::IPv4)) {
                    init(Type::IPv4);
                    resolve = false;
                }
                else if (IsCorrect(address, Type::IPv6)) {
                    init(Type::IPv6);
                    resolve = false;
                }
            }
            if (resolve) {
                Resolve(address, type);
            }
        }
        IPAddress(const std::string &address, uint16_t port, Type type = Type::Unknown) : IPAddress(address, type) {
            SetPort(port);
        }
        IPAddress(unsigned long address) : IPAddress() {
            (reinterpret_cast<sockaddr_in *>(this->address))->sin_addr.s_addr = htonl(address);
        }
        IPAddress(unsigned long address, uint16_t port) : IPAddress(address) {
            SetPort(port);
        }
        IPAddress(const IPAddress &source) {
            switch (source.GetType()) {
            case Type::IPv6:
                address = reinterpret_cast<sockaddr *>(new sockaddr_in6);
                std::memcpy(address, source.address, sizeof(sockaddr_in6));
                break;
            case Type::IPv4:
            default:
                address = reinterpret_cast<sockaddr *>(new sockaddr_in);
                std::memcpy(address, source.address, sizeof(sockaddr_in));
            }
        }
        IPAddress(IPAddress &&source) {
            address = source.address;
            source.address = reinterpret_cast<sockaddr *>(new sockaddr_in);
            std::memset(source.address, 0, sizeof(sockaddr_in));
            (reinterpret_cast<sockaddr_in *>(source.address))->sin_family = AF_INET;
        }
        virtual ~IPAddress() {
            delete address;
        }
        IPAddress &operator=(const IPAddress &source) {
            delete address;
            switch (source.GetType()) {
            case Type::IPv6:
                address = reinterpret_cast<sockaddr *>(new sockaddr_in6);
                std::memcpy(address, source.address, sizeof(sockaddr_in6));
                break;
            case Type::IPv4:
            default:
                address = reinterpret_cast<sockaddr *>(new sockaddr_in);
                std::memcpy(address, source.address, sizeof(sockaddr_in));
            }
            return *this;
        }
        IPAddress &operator=(IPAddress &&source) {
            delete address;
            address = source.address;
            source.address = reinterpret_cast<sockaddr *>(new sockaddr_in);
            std::memset(source.address, 0, sizeof(sockaddr_in));
            (reinterpret_cast<sockaddr_in *>(source.address))->sin_family = AF_INET;
            return *this;
        }
        IPAddress &Resolve(const std::string &address, Type type = Type::IPv4) {
            addrinfo hints;
            std::memset(&hints, 0, sizeof(addrinfo));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            addrinfo *result = NULL;
            if (getaddrinfo(address.c_str(), NULL, &hints, &result) == 0) {
                for (addrinfo *ptr = result; ptr != NULL; ptr = ptr->ai_next) {
                    switch (ptr->ai_family) {
                    case AF_INET:
                        if ((type != Type::IPv4) && (type != Type::Unknown)) {
                            break;
                        }
                        delete this->address;
                        this->address = reinterpret_cast<sockaddr *>(new sockaddr_in);
                        std::memcpy(this->address, ptr->ai_addr, sizeof(sockaddr_in));
                        freeaddrinfo(result);
                        type = Type::IPv4;
                        return *this;
                    case AF_INET6:
                        if ((type != Type::IPv6) && (type != Type::Unknown)) {
                            break;
                        }
                        delete this->address;
                        this->address = reinterpret_cast<sockaddr *>(new sockaddr_in6);
                        std::memcpy(this->address, ptr->ai_addr, sizeof(sockaddr_in6));
                        freeaddrinfo(result);
                        type = Type::IPv6;
                        return *this;
                    default:
                        break;
                    }
                }
                freeaddrinfo(result);
            }
            throw std::runtime_error("Cannot resolve address: " + address);
        }
        operator std::string() const {
            char buffer[INET6_ADDRSTRLEN];
            switch (GetType()) {
            case Type::IPv6:
                if (inet_ntop(AF_INET6, &(reinterpret_cast<sockaddr_in6 *>(address))->sin6_addr, buffer, INET6_ADDRSTRLEN) != NULL) {
                    return std::string(buffer);
                }
                throw std::runtime_error("Cannot convert IPv6 address structure");
            case Type::IPv4:
            default:
                if (inet_ntop(AF_INET, &(reinterpret_cast<sockaddr_in *>(address))->sin_addr, buffer, INET6_ADDRSTRLEN) != NULL) {
                    return std::string(buffer);
                }
                throw std::runtime_error("Cannot convert IPv4 address structure");
            }
        }
        bool operator==(const IPAddress &compare) const noexcept {
            return (static_cast<std::string>(*this) == static_cast<std::string>(compare)) && (this->GetPort() == compare.GetPort());
        }
        void SetPort(uint16_t port) {
            switch (GetType()) {
            case Type::IPv6:
                (reinterpret_cast<sockaddr_in6 *>(address))->sin6_port = htons(port);
                break;
            case Type::IPv4:
            default:
                (reinterpret_cast<sockaddr_in *>(address))->sin_port = htons(port);
            }
        }
        uint16_t GetPort() const {
            switch (GetType()) {
            case Type::IPv6:
                return ntohs((reinterpret_cast<sockaddr_in6 *>(address))->sin6_port);
                break;
            case Type::IPv4:
            default:
                return ntohs((reinterpret_cast<sockaddr_in *>(address))->sin_port);
            }
        }
        Type GetType() const {
            switch (address->sa_family) {
            case AF_INET6:
                return Type::IPv6;
            case AF_INET:
            default:
                return Type::IPv4;
            }
        }
        sockaddr *GetSockAddr() const {
            return address;
        }
        socklen_t GetSockAddrLength() const {
            switch (GetType()) {
            case Type::IPv6:
                return sizeof(sockaddr_in6);
            case Type::IPv4:
            default:
                return sizeof(sockaddr_in);
            }
        }
        static inline bool IsCorrect(const std::string &address, Type type = Type::IPv4) {
            switch (type) {
            case Type::IPv4:
                return std::regex_match(address, std::regex("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"));
            case Type::IPv6:
                return std::regex_match(address, std::regex("^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"));
            default:
                return IsCorrect(address, Type::IPv4) || IsCorrect(address, Type::IPv6);
            }
        }
        static inline int GetFamily(Type type) {
            switch (type) {
            case Type::IPv6:
                return AF_INET6;
            case Type::IPv4:
            default:
                return AF_INET;
            }
        }
    private:
        sockaddr *address;
    };

    Switchable::Switchable()
        : enabled(false)
    {
    }

    bool Switchable::IsEnabled() const
    {
        return enabled;
    }

    void Switchable::Disable() noexcept
    {
        enabled = false;
    }

    class InputDevice : public Switchable {
    public:
        InputDevice() { }
        InputDevice(const InputDevice &) = delete;
        InputDevice(InputDevice &&) = delete;
        virtual ~InputDevice() {
            Disable();
        }
        InputDevice &operator=(const InputDevice &) = delete;
        void Enable(const std::string &device, uint32_t samplingRate, uint8_t channels, uint8_t bitsPerChannel) {
            enabled = true;
            thread = std::thread(DeviceThread, this, device, samplingRate, channels, bitsPerChannel);
        }
        void Disable() noexcept {
            Switchable::Disable();
            if (thread.joinable()) {
                thread.join();
            }
        }
        std::string GetError() {
            std::lock_guard<std::mutex> lock(access);
            return errorDescription;
        }
        std::vector<uint8_t> GetData() {
            std::vector<uint8_t> data;
            {
                std::lock_guard<std::mutex> lock(access);
                data = std::move(this->data);
            }
            return data;
        }
    private:
        static void DeviceThread(InputDevice *instance, const std::string &device, uint32_t samplingRate, uint8_t channels, uint8_t bitsPerChannel) {
            uint8_t *buffer = nullptr;
            snd_pcm_t *handle = nullptr;
            snd_pcm_hw_params_t *params = nullptr;
            try {
                if ((bitsPerChannel != 8) && (bitsPerChannel != 16)) {
                    throw std::runtime_error("Unsupported channel bits value");
                }

                int error = snd_pcm_open(&handle, device.c_str(), SND_PCM_STREAM_CAPTURE, 0);
                if (error < 0) {
                    throw std::runtime_error("Cannot open PCM device: " + device + " (" + std::string(snd_strerror(error)) + ")");
                }

                snd_pcm_hw_params_alloca(&params);
                error = snd_pcm_hw_params_any(handle, params);
                if (error < 0) {
                    throw std::runtime_error("Cannot fill device configuration (" + std::string(snd_strerror(error)) + ")");
                }
                error = snd_pcm_hw_params_set_access(handle, params, SND_PCM_ACCESS_RW_INTERLEAVED);
                if (error < 0) {
                    throw std::runtime_error("Cannot set device access type (" + std::string(snd_strerror(error)) + ")");
                }
                error = snd_pcm_hw_params_set_format(handle, params, (bitsPerChannel != 8) ? SND_PCM_FORMAT_S16_LE : SND_PCM_FORMAT_U8);
                if (error < 0) {
                    throw std::runtime_error("Cannot set channel bits value: " + std::to_string(bitsPerChannel) + " (" + std::string(snd_strerror(error)) + ")");
                }
                error = snd_pcm_hw_params_set_channels(handle, params, channels);
                if (error < 0) {
                    throw std::runtime_error("Cannot set channels number: " + std::to_string(channels) + " (" + std::string(snd_strerror(error)) + ")");
                }
                unsigned rate = samplingRate; int dir;
                error = snd_pcm_hw_params_set_rate_near(handle, params, &rate, &dir);
                if (error < 0) {
                    throw std::runtime_error("Cannot set samplig rate: " + std::to_string(samplingRate) + " (" + std::string(snd_strerror(error)) + ")");
                }
                if (rate != samplingRate) {
                    throw std::runtime_error("Cannot set samplig rate: " + std::to_string(samplingRate));
                }
                snd_pcm_uframes_t frames = UDP_STREAM_PERIOD_SIZE;
                error = snd_pcm_hw_params_set_period_size_near(handle, params, &frames, &dir);
                if (error < 0) {
                    throw std::runtime_error("Cannot set period size: " + std::to_string(UDP_STREAM_PERIOD_SIZE) + " (" + std::string(snd_strerror(error)) + ")");
                }

                error = snd_pcm_hw_params(handle, params);
                if (error < 0) {
                    throw std::runtime_error("Cannot set hardware parameters (" + std::string(snd_strerror(error)) + ")");
                }

                snd_pcm_hw_params_get_period_size(params, &frames, &dir);
                std::size_t size = frames * (bitsPerChannel >> 3) * channels;
                buffer = new uint8_t[size];

                while (instance->enabled) {
                    error = snd_pcm_readi(handle, buffer, frames);
                    if (error == -EPIPE) {
                        /* EPIPE: Overrun */
                        snd_pcm_prepare(handle);
                    } else if (error < 0) {
                        throw std::runtime_error("Error while reading from device (" + std::string(snd_strerror(error)) + ")");
                    }
                    std::lock_guard<std::mutex> lock(instance->access);
                    std::size_t offset = instance->data.size(), bytes = error * (bitsPerChannel >> 3) * channels;
                    instance->data.resize(offset + bytes);
                    std::memcpy(&instance->data.data()[offset], buffer, bytes);
                }
            }
            catch (std::exception &catched) {
                std::lock_guard<std::mutex> lock(instance->access);
                instance->errorDescription = catched.what();
                instance->enabled = false;
            }

            if (handle != nullptr) {
                snd_pcm_drain(handle);
                snd_pcm_close(handle);
            }
            if (buffer != nullptr) {
                delete[] buffer;
            }
        }
        std::vector<uint8_t> data;
        std::string errorDescription;
        std::thread thread;
        std::mutex access;
    };

    OutputDevice::OutputDevice() {
    }

    OutputDevice::~OutputDevice() {
        Disable();
    }

    void OutputDevice::Enable(const std::string &device, uint32_t samplingRate, uint8_t channels, uint8_t bitsPerChannel) {
        enabled = true;
        thread = std::thread(DeviceThread, this, device, samplingRate, channels, bitsPerChannel);
    }

    void OutputDevice::Disable() noexcept {
        Switchable::Disable();
        if (thread.joinable()) {
            thread.join();
        }
    }

    std::string OutputDevice::GetError() {
        std::lock_guard<std::mutex> lock(access);
        return errorDescription;
    }

    void OutputDevice::SetData(const uint8_t *data, std::size_t size) {
        std::lock_guard<std::mutex> lock(access);
        std::size_t offset = this->data.size();
        this->data.resize(offset + size);
        std::memcpy(&this->data.data()[offset], data, size);
    }

    void OutputDevice::DeviceThread(OutputDevice *instance, const std::string &device, uint32_t samplingRate, uint8_t channels, uint8_t bitsPerChannel) {
        uint8_t *buffer = nullptr;
        snd_pcm_t *handle = nullptr;
        snd_pcm_hw_params_t *params = nullptr;
        try {
            if ((bitsPerChannel != 8) && (bitsPerChannel != 16)) {
                throw std::runtime_error("Unsupported channel bits value");
            }

            int error = snd_pcm_open(&handle, device.c_str(), SND_PCM_STREAM_PLAYBACK, 0);
            if (error < 0) {
                throw std::runtime_error("Cannot open PCM device: " + device + " (" + std::string(snd_strerror(error)) + ")");
            }

            snd_pcm_hw_params_alloca(&params);
            error = snd_pcm_hw_params_any(handle, params);
            if (error < 0) {
                throw std::runtime_error("Cannot fill device configuration (" + std::string(snd_strerror(error)) + ")");
            }
            error = snd_pcm_hw_params_set_access(handle, params, SND_PCM_ACCESS_RW_INTERLEAVED);
            if (error < 0) {
                throw std::runtime_error("Cannot set device access type (" + std::string(snd_strerror(error)) + ")");
            }
            error = snd_pcm_hw_params_set_format(handle, params, (bitsPerChannel != 8) ? SND_PCM_FORMAT_S16_LE : SND_PCM_FORMAT_U8);
            if (error < 0) {
                throw std::runtime_error("Cannot set bits per channel value: " + std::to_string(bitsPerChannel) + " (" + std::string(snd_strerror(error)) + ")");
            }
            error = snd_pcm_hw_params_set_channels(handle, params, channels);
            if (error < 0) {
                throw std::runtime_error("Cannot set channels number: " + std::to_string(channels) + " (" + std::string(snd_strerror(error)) + ")");
            }
            unsigned rate = samplingRate, bufferTime; int dir;
            error = snd_pcm_hw_params_set_rate_near(handle, params, &rate, &dir);
            if (error < 0) {
                throw std::runtime_error("Cannot set samplig rate: " + std::to_string(samplingRate) + " (" + std::string(snd_strerror(error)) + ")");
            }
            if (rate != samplingRate) {
                throw std::runtime_error("Cannot set samplig rate: " + std::to_string(samplingRate));
            }
            bufferTime = UDP_STREAM_BUFFER_TIME;
            error = snd_pcm_hw_params_set_buffer_time_near(handle, params, &bufferTime, &dir);
            if (error < 0) {
                throw std::runtime_error("Cannot set buffer time: " + std::to_string(UDP_STREAM_BUFFER_TIME) + " (" + std::string(snd_strerror(error)) + ")");
            }
            snd_pcm_uframes_t frames = UDP_STREAM_PERIOD_SIZE;
            error = snd_pcm_hw_params_set_period_size_near(handle, params, &frames, &dir);
            if (error < 0) {
                throw std::runtime_error("Cannot set period size: " + std::to_string(UDP_STREAM_PERIOD_SIZE) + " (" + std::string(snd_strerror(error)) + ")");
            }

            error = snd_pcm_hw_params(handle, params);
            if (error < 0) {
                throw std::runtime_error("Cannot set hardware parameters (" + std::string(snd_strerror(error)) + ")");
            }

            snd_pcm_hw_params_get_period_size(params, &frames, &dir);
            std::size_t size = frames * (bitsPerChannel >> 3) * channels;
            buffer = new uint8_t[size];

            while (instance->enabled) {
                bool wait = false;
                {
                    std::lock_guard<std::mutex> lock(instance->access);
                    if (instance->data.size() < size) {
                        wait = true;
                    }
                    else {
                        std::memcpy(buffer, instance->data.data(), size);
                        instance->data.erase(instance->data.begin(), instance->data.begin() + size);
                    }
                }
                if (wait) {
                    std::this_thread::sleep_for(std::chrono::microseconds(size * 250000 / (samplingRate * channels * (bitsPerChannel >> 3))));
                    continue;
                }
                error = snd_pcm_writei(handle, buffer, frames);
                if (error == -EPIPE) {
                    /* EPIPE: Underrun */
                    snd_pcm_prepare(handle);
                }
                else if (error < 0) {
                    throw std::runtime_error("Error while writing to device (" + std::string(snd_strerror(error)) + ")");
                }
            }
        }
        catch (std::exception &catched) {
            std::lock_guard<std::mutex> lock(instance->access);
            instance->errorDescription = catched.what();
            instance->enabled = false;
        }

        if (handle != nullptr) {
            snd_pcm_drain(handle);
            snd_pcm_close(handle);
        }
        if (buffer != nullptr) {
            delete[] buffer;
        }
    }

    struct PacketHeader {
        uint32_t identifier;
        uint32_t samplingRate;
        uint8_t channels;
        uint8_t bitsPerChannel;
    };

    class UDPServer : public Switchable {
    public:
        struct OutboundData {
            std::vector<uint8_t> stream;
            IPAddress address;
        };
        using DataHandler = std::function<void(const IPAddress &address, const std::vector<uint8_t> &input)>;
        UDPServer() : Switchable() { }
        UDPServer(const UDPServer &) = delete;
        UDPServer(UDPServer &&) = delete;
        UDPServer &operator=(const UDPServer &) = delete;
        void SetHandler(DataHandler handler) {
            this->handler = handler;
        }
        void Send(const IPAddress &address, const std::vector<uint8_t> &stream) {
            std::lock_guard<std::mutex> lock(access);
            outbound.push_back({ stream, address });
        }
        void Enable(const std::string &address, uint16_t port) {
            IPAddress addr(address, port);

            int sock;
            if ((sock = socket(IPAddress::GetFamily(addr.GetType()), SOCK_DGRAM, IPPROTO_UDP)) == -1) {
                throw std::runtime_error("Cannot enable service (socket error)");
            }

            int flags = fcntl(sock, F_GETFL, 0);
            if ((flags == -1) || fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
                close(sock);
                throw std::runtime_error("Cannot enable service (fcntl error)");
            }

            int enable = 1;
            if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char *>(&enable), sizeof(enable)) == -1) {
                close(sock);
                throw std::runtime_error("Cannot enable service (setsockopt error)");
            }

            if (bind(sock, addr.GetSockAddr(), addr.GetSockAddrLength()) == -1) {
                close(sock);
                throw std::runtime_error("Cannot enable service (bind error)");
            }

            enabled = true;
            std::vector<uint8_t> input;
            input.resize(UDP_SERVER_PACKET_LENGTH);
            outbound.clear();
            OutboundData *data;
            socklen_t length;

            while (enabled) {
                while ((data = GetOutbound()) != nullptr) {
                    length = data->address.GetSockAddrLength();
                    while (true) {
                        int bytes = sendto(sock, reinterpret_cast<char *>(data->stream.data()), static_cast<int>(data->stream.size()), 0, data->address.GetSockAddr(), length);
                        if ((bytes != -1) || ((errno != EWOULDBLOCK) && (errno != EAGAIN))) {
                            break;
                        }
                        std::this_thread::sleep_for(std::chrono::microseconds(UDP_SERVER_NOP_DELAY));
                    }
                    delete data;
                }
                length = addr.GetSockAddrLength();
                int bytes = recvfrom(sock, reinterpret_cast<char *>(input.data()), static_cast<int>(input.size()), 0, addr.GetSockAddr(), &length);
                if (bytes == -1) {
                    std::this_thread::sleep_for(std::chrono::microseconds(UDP_SERVER_NOP_DELAY));
                    continue;
                }
                if ((handler != nullptr) && bytes) {
                    handler(addr, std::vector<uint8_t>(input.begin(), input.begin() + bytes));
                }
            }

            close(sock);
        }
    private:
        OutboundData *GetOutbound() {
            std::lock_guard<std::mutex> lock(access);
            if (outbound.empty()) {
                return nullptr;
            }
            OutboundData *outbound = new OutboundData;
            outbound->stream = this->outbound.begin()->stream;
            outbound->address = this->outbound.begin()->address;
            this->outbound.erase(this->outbound.begin());
            return outbound;
        }
        std::vector<OutboundData> outbound;
        DataHandler handler;
        std::mutex access;
    };

    class UDPClient : Switchable {
    public:
        UDPClient() : connected(false) { };
        UDPClient(const UDPClient &) = delete;
        UDPClient(UDPClient &&) = delete;
        virtual ~UDPClient() {
            Disable();
        }
        UDPClient &operator=(const UDPClient &) = delete;
        void Enable(const std::string &address, uint16_t port) {
            addr = IPAddress(address, port);

            if ((sock = socket(IPAddress::GetFamily(addr.GetType()), SOCK_DGRAM, IPPROTO_UDP)) == -1) {
                throw std::runtime_error("Cannot initialize connection (socket error)");
            }

            int flags = fcntl(sock, F_GETFL, 0);
            if ((flags == -1) || fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
                close(sock);
                throw std::runtime_error("Cannot initialize connection (fcntl error)");
            }

            enabled = true;
        }
        void Disable() noexcept {
            if (enabled) {
                close(sock);
            }
            Switchable::Disable();
        }
        std::vector<uint8_t> Receive() const {
            std::vector<uint8_t> stream;
            stream.resize(UDP_SERVER_PACKET_LENGTH);
            socklen_t length = addr.GetSockAddrLength();
            int bytes = recvfrom(sock, reinterpret_cast<char *>(stream.data()), static_cast<int>(stream.size()), 0, addr.GetSockAddr(), &length);
            if (bytes == -1) {
                return std::vector<uint8_t>();
            }
            return std::vector<uint8_t>(stream.begin(), stream.begin() + bytes);
        }
        void Send(const std::vector<uint8_t> &stream) const {
#ifdef _WIN32
            int length = addr.GetSockAddrLength();
#else
            socklen_t length = addr.GetSockAddrLength();
#endif
            while (true) {
                int bytes = sendto(sock, reinterpret_cast<const char *>(stream.data()), static_cast<int>(stream.size()), 0, addr.GetSockAddr(), length);
                if ((bytes != -1) || ((errno != EWOULDBLOCK) && (errno != EAGAIN))) {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::microseconds(UDP_SERVER_NOP_DELAY));
            }

            sendto(sock, reinterpret_cast<const char *>(stream.data()), static_cast<int>(stream.size()), 0, addr.GetSockAddr(), length);
        }
    private:
        int sock;
        IPAddress addr;
        bool connected;
    };

    Service::Service(const ExceptionHandler &exceptionHandler, const LogHandler &logHandler)
        : Switchable(), exceptionHandler(exceptionHandler), logHandler(logHandler)
    {
    }

    Service::~Service()
    {
        Disable();
    }

    void Service::Enable(
        const std::string &address,
        uint16_t port,
        const std::string &device,
        uint32_t samplingRate,
        uint8_t channels,
        uint8_t bitsPerChannel
    )
    {
        enabled = true;
        thread = std::thread(ServiceThread, this, address, port, device, samplingRate, channels, bitsPerChannel);
    }

    void Service::Disable() noexcept
    {
        Switchable::Disable();
        if (thread.joinable()) {
            thread.join();
        }
    }

    void Service::ServiceThread(
        Service *instance,
        const std::string &address,
        uint16_t port,
        const std::string &device,
        uint32_t samplingRate,
        uint8_t channels,
        uint8_t bitsPerChannel
    ) noexcept {
        ExceptionHandler exceptionHandler;
        LogHandler logHandler;
        UDPServer server;
        InputDevice inputDevice;

        {
            std::lock_guard<std::mutex> lock(instance->access);
            exceptionHandler = instance->exceptionHandler;
            logHandler = instance->logHandler;
        }

        auto handleException = [&](const std::exception &exception) {
            if (exceptionHandler != nullptr) {
                exceptionHandler(exception);
            }
        };

        auto printText = [&](const std::string &text) {
            if (logHandler != nullptr) {
                logHandler(text);
            }
        };

        std::mutex access;
        struct Registered {
            IPAddress address;
            std::time_t timeout;
        } *registered;

        std::thread serverThread([&]() {
            printText("Starting service on: " + address + ":" + std::to_string(port));
            server.SetHandler([&](const IPAddress &address, const std::vector<uint8_t> &input) {
                for (std::size_t i = 0; i < input.size(); i++) {
                    std::vector<uint8_t> status;
                    switch (input.data()[0]) {
                    case UDP_STREAM_CLIENT_REQUEST_REGISTER:
                    {
                        std::lock_guard<std::mutex> lock(access);
                        if ((registered != nullptr) && registered->address == address) {
                            registered->timeout = std::time(nullptr) + UDP_STREAM_REGISTER_TIMEOUT;
                        }
                        else if (registered == nullptr) {
                            registered = new Registered({ address, std::time(nullptr) + UDP_STREAM_REGISTER_TIMEOUT });
                            printText("Client " + static_cast<std::string>(address) + ":" + std::to_string(address.GetPort()) + " registered");
                        }
                    }
                    break;
                    case UDP_STREAM_CLIENT_REQUEST_UNREGISTER:
                    {
                        std::lock_guard<std::mutex> lock(access);
                        if ((registered != nullptr) && registered->address == address) {
                            printText("Client " + static_cast<std::string>(address) + ":" + std::to_string(address.GetPort()) + " unregistered");
                            delete registered;
                            registered = nullptr;
                        }
                    }
                    break;
                    default:
                        break;
                    }
                }
            });

            try {
                server.Enable(address, port);
            }
            catch (std::exception &exception) {
                handleException(exception);
                instance->enabled = false;
            }
        });

        while (instance->enabled && !server.IsEnabled()) {
            std::this_thread::sleep_for(std::chrono::microseconds(UDP_STREAM_NOP_DELAY));
        }

        auto handleTimeout = [&]() {
            std::lock_guard<std::mutex> lock(access);
            if ((registered != nullptr) && (registered->timeout < std::time(nullptr))) {
                printText("Client " + static_cast<std::string>(registered->address) + ":" + std::to_string(registered->address.GetPort()) + " unregistered");
                delete registered;
                registered = nullptr;
            }
        };

        uint32_t identifier = 0;
        try {
            inputDevice.Enable(device, samplingRate, channels, bitsPerChannel);
            while (instance->enabled) {
                std::string error = inputDevice.GetError();
                if (!error.empty()) {
                    throw std::runtime_error(error.c_str());
                }
                handleTimeout();
                std::vector<uint8_t> stream = inputDevice.GetData();
                if (!stream.empty()) {
                    Registered client;
                    {
                        std::lock_guard<std::mutex> lock(access);
                        if (registered == nullptr) {
                            std::this_thread::sleep_for(std::chrono::microseconds(UDP_STREAM_NOP_DELAY));
                            continue;
                        }
                        client = *registered;
                    }
                    while (!stream.empty()) {
                        PacketHeader header = {
                            identifier,
                            samplingRate,
                            channels,
                            bitsPerChannel
                        };
                        std::vector<uint8_t> packet;
                        std::size_t size = std::min(stream.size(), UDP_SERVER_PACKET_LENGTH - sizeof(PacketHeader));
                        packet.resize(sizeof(PacketHeader) + size);
                        std::memcpy(packet.data(), &header, sizeof(PacketHeader));
                        std::memcpy(&packet.data()[sizeof(PacketHeader)], stream.data(), size);
                        server.Send(client.address, packet);
                        stream.erase(stream.begin(), stream.begin() + size);
                        std::this_thread::sleep_for(std::chrono::microseconds(size * 250000 / (samplingRate * channels * (bitsPerChannel >> 3))));
                        identifier++;
                    }
                }
                else {
                    std::this_thread::sleep_for(std::chrono::microseconds(UDP_STREAM_NOP_DELAY));
                }
            }
        }
        catch (std::exception &exception) {
            handleException(exception);
            instance->enabled = false;
        }
        server.Disable();
        if (serverThread.joinable()) {
            serverThread.join();
        }
        if (registered != nullptr) {
            delete registered;
        }
    }

    Client::Client(const DataHandler &dataHandler, const ExceptionHandler &exceptionHandler)
        : Switchable(), dataHandler(dataHandler), exceptionHandler(exceptionHandler)
    {
    }

    Client::~Client()
    {
        Disable();
    }

    void Client::Enable(const std::string &address, uint16_t port, const std::string &device)
    {
        enabled = true;
        thread = std::thread(ClientThread, this, address, port, device);
    }

    void Client::Disable() noexcept
    {
        Switchable::Disable();
        if (thread.joinable()) {
            thread.join();
        }
    }

    void Client::ClientThread(
        Client *instance,
        const std::string &address,
        uint16_t port,
        const std::string &device
    ) noexcept
    {
        ExceptionHandler exceptionHandler;
        UDPClient client;

        {
            std::lock_guard<std::mutex> lock(instance->access);
            exceptionHandler = instance->exceptionHandler;
        }

        std::mutex streamAccess;
        std::vector<uint8_t> stream;
        std::atomic_bool handle(true);
        std::thread handlerThread([&]() {
            DataHandler dataHandler;
            {
                std::lock_guard<std::mutex> lock(instance->access);
                dataHandler = instance->dataHandler;
            }

            std::vector<uint8_t> handlerStream;
            while (handle) {
                {
                    std::lock_guard<std::mutex> lock(streamAccess);
                    handlerStream = std::move(stream);
                }
                if (!handlerStream.empty()) {
                    PacketHeader header = *reinterpret_cast<PacketHeader *>(handlerStream.data());
                    dataHandler(header.samplingRate, header.channels, header.bitsPerChannel, &handlerStream.data()[sizeof(PacketHeader)], handlerStream.size() - sizeof(PacketHeader));
                }
                else {
                    std::this_thread::sleep_for(std::chrono::microseconds(UDP_STREAM_NOP_DELAY));
                }
            }
        });

        auto handleException = [&](const std::exception &exception) {
            if (exceptionHandler != nullptr) {
                exceptionHandler(exception);
            }
        };

        auto createRequest = [&](uint8_t type) -> std::vector<uint8_t> {
            std::vector<uint8_t> request;
            request.push_back(type);
            return request;
        };

        bool registered = false;
        try {
            client.Enable(address, port);

            client.Send(createRequest(UDP_STREAM_CLIENT_REQUEST_REGISTER));
            std::time_t timeout = std::time(nullptr) + (UDP_STREAM_REGISTER_TIMEOUT >> 1);
            registered = true;

            uint32_t last = 0;
            while (instance->enabled) {
                if (timeout < std::time(nullptr)) {
                    client.Send(createRequest(UDP_STREAM_CLIENT_REQUEST_REGISTER));
                    timeout = std::time(nullptr) + (UDP_STREAM_REGISTER_TIMEOUT >> 1);
                }
                std::vector<uint8_t> received = client.Receive();
                if (received.size() > sizeof(PacketHeader)) {
                    uint32_t identifier = reinterpret_cast<PacketHeader *>(received.data())->identifier;
                    if (!last || (last < identifier)) {
                        std::lock_guard<std::mutex> lock(streamAccess);
                        stream = std::move(received);
                    }
                    last = identifier;
                }
                else {
                    std::this_thread::sleep_for(std::chrono::microseconds(UDP_STREAM_NOP_DELAY));
                }
            }
        }
        catch (std::exception &exception) {
            handleException(exception);
            instance->enabled = false;
        }
        if (registered) {
            client.Send(createRequest(UDP_STREAM_CLIENT_REQUEST_UNREGISTER));
        }
        client.Disable();
        handle = false;
        if (handlerThread.joinable()) {
            handlerThread.join();
        }
    }
}
