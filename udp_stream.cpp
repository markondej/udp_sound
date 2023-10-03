#include "udp_stream.hpp"
#include <mutex>
#include <regex>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#define ALSA_PCM_NEW_HW_PARAMS_API
#include <alsa/asoundlib.h>

#ifndef UDP_SERVER_PACKET_LENGTH
#define UDP_SERVER_PACKET_LENGTH 65507
#endif

#define UDP_SERVER_NOP_DELAY 1

#define UDP_STREAM_NOP_DELAY 10
#define UDP_STREAM_REGISTER_TIMEOUT 5000
#define UDP_STREAM_PERIOD_DURATION 25
#define UDP_STREAM_BUFFERED_PERIODS 4
#define UDP_STREAM_SOUND_MIN_DURATION 125
#define UDP_STREAM_SOUND_DURATION_LIMIT 500

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
            reinterpret_cast<sockaddr_in *>(address)->sin_family = AF_INET;
        }
        IPAddress(const std::string &address, Type type = Type::Unknown) : IPAddress() {
            auto init = [&](Type type) {
                switch (type) {
                case Type::IPv6:
                    delete this->address;
                    this->address = reinterpret_cast<sockaddr *>(new sockaddr_in6);
                    std::memset(this->address, 0, sizeof(sockaddr_in6));
                    reinterpret_cast<sockaddr_in6 *>(this->address)->sin6_family = AF_INET6;
                    if (inet_pton(AF_INET6, address.c_str(), &reinterpret_cast<sockaddr_in6 *>(this->address)->sin6_addr) <= 0) {
                        delete this->address;
                        throw std::runtime_error("Incorrect IPv6 address provided");
                    }
                    break;
                case Type::IPv4:
                default:
                    if (inet_pton(AF_INET, address.c_str(), &reinterpret_cast<sockaddr_in *>(this->address)->sin_addr) <= 0) {
                        delete this->address;
                        throw std::runtime_error("Incorrect IPv4 address provided");
                    }
                }
            };
            if ((type != Type::Unknown) && IsCorrect(address, type)) {
                init(type);
                return;
            } else if (type == Type::Unknown) {
                if (IsCorrect(address, Type::IPv4)) {
                    init(Type::IPv4);
                    return;
                } else if (IsCorrect(address, Type::IPv6)) {
                    init(Type::IPv6);
                    return;
                }
            }
            Resolve(address, type);
        }
        IPAddress(const std::string &address, uint16_t port, Type type = Type::Unknown) : IPAddress(address, type) {
            SetPort(port);
        }
        IPAddress(unsigned long address) : IPAddress() {
            reinterpret_cast<sockaddr_in *>(this->address)->sin_addr.s_addr = htonl(address);
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
            reinterpret_cast<sockaddr_in *>(source.address)->sin_family = AF_INET;
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
            reinterpret_cast<sockaddr_in *>(source.address)->sin_family = AF_INET;
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
            throw std::runtime_error("Cannot resolve host address: " + address);
        }
        operator std::string() const {
            char buffer[INET6_ADDRSTRLEN];
            switch (GetType()) {
            case Type::IPv6:
                if (inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6 *>(address)->sin6_addr, buffer, INET6_ADDRSTRLEN) != NULL) {
                    return std::string(buffer);
                }
                throw std::runtime_error("Cannot convert IPv6 address structure");
            case Type::IPv4:
            default:
                if (inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in *>(address)->sin_addr, buffer, INET6_ADDRSTRLEN) != NULL) {
                    return std::string(buffer);
                }
                throw std::runtime_error("Cannot convert IPv4 address structure");
            }
        }
        bool operator==(const IPAddress &compare) const {
            return (static_cast<std::string>(*this) == static_cast<std::string>(compare)) && (this->GetPort() == compare.GetPort());
        }
        void SetPort(uint16_t port) {
            switch (GetType()) {
            case Type::IPv6:
                reinterpret_cast<sockaddr_in6 *>(address)->sin6_port = htons(port);
                break;
            case Type::IPv4:
            default:
                reinterpret_cast<sockaddr_in *>(address)->sin_port = htons(port);
            }
        }
        uint16_t GetPort() const {
            switch (GetType()) {
            case Type::IPv6:
                return ntohs(reinterpret_cast<sockaddr_in6 *>(address)->sin6_port);
                break;
            case Type::IPv4:
            default:
                return ntohs(reinterpret_cast<sockaddr_in *>(address)->sin_port);
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
        static bool IsCorrect(const std::string &address, Type type = Type::IPv4) {
            switch (type) {
            case Type::IPv4:
                return std::regex_match(address, std::regex("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"));
            case Type::IPv6:
                return std::regex_match(address, std::regex("^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"));
            default:
                return IsCorrect(address, Type::IPv4) || IsCorrect(address, Type::IPv6);
            }
        }
        static int GetFamily(Type type) {
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

    Switchable::Switchable() : enabled(false)
    {
    }

    bool Switchable::IsEnabled() const
    {
        return enabled.load();
    }

    bool Switchable::Disable()
    {
        return enabled.exchange(false);
    }

    bool Switchable::Enable()
    {
        return !enabled.exchange(true);
    }

    class InputDevice : public Switchable {
    public:
        InputDevice() : Switchable(), data(nullptr), error(nullptr) { }
        InputDevice(const InputDevice &) = delete;
        InputDevice(InputDevice &&) = delete;
        virtual ~InputDevice() {
            Disable();
            auto data = this->data.exchange(nullptr);
            if (data != nullptr) {
                delete data;
            }
            auto error = this->error.exchange(nullptr);
            if (error != nullptr) {
                delete error;
            }
        }
        InputDevice &operator=(const InputDevice &) = delete;
        void Enable(const std::string &device, uint32_t samplingRate, uint8_t channels, uint8_t bitsPerChannel) {
            if (!Switchable::Enable()) {
                return;
            }
            auto data = this->data.exchange(nullptr);
            if (data != nullptr) {
                delete data;
            }
            try {
                thread = std::thread(DeviceThread, this, device, samplingRate, channels, bitsPerChannel);
            } catch (...) {
                Switchable::Disable();
                throw;
            }
        }
        bool Disable() {
            static std::mutex access;
            std::lock_guard<std::mutex> lock(access);
            if (Switchable::Disable()) {
                thread.join();
                return true;
            }
            return false;
        }
        std::string GetError() {
            std::string error;
            auto stored = this->error.exchange(nullptr);
            if (stored != nullptr) {
                error = std::move(*stored);
                delete stored;
            }
            return error;
        }
        std::vector<uint8_t> *GetData() {
            return data.exchange(nullptr);
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
                    throw std::runtime_error("Cannot set sampling rate: " + std::to_string(samplingRate) + " (" + std::string(snd_strerror(error)) + ")");
                }
                if (rate != samplingRate) {
                    throw std::runtime_error("Cannot set sampling rate: " + std::to_string(samplingRate));
                }
                snd_pcm_uframes_t frames = samplingRate * UDP_STREAM_PERIOD_DURATION / 1000;
                error = snd_pcm_hw_params_set_period_size_near(handle, params, &frames, &dir);
                if (error < 0) {
                    throw std::runtime_error("Cannot set period duration: " + std::to_string(UDP_STREAM_PERIOD_DURATION) + " ms (" + std::string(snd_strerror(error)) + ")");
                }
                frames *= UDP_STREAM_BUFFERED_PERIODS;
                error = snd_pcm_hw_params_set_buffer_size_near(handle, params, &frames);
                if (error < 0) {
                    throw std::runtime_error("Cannot set buffer size: " + std::to_string(samplingRate * UDP_STREAM_PERIOD_DURATION * UDP_STREAM_BUFFERED_PERIODS / 1000) + " (" + std::string(snd_strerror(error)) + ")");
                }

                error = snd_pcm_hw_params(handle, params);
                if (error < 0) {
                    throw std::runtime_error("Cannot set hardware parameters (" + std::string(snd_strerror(error)) + ")");
                }

                snd_pcm_hw_params_get_period_size(params, &frames, &dir);
                std::size_t size = frames * (bitsPerChannel >> 3) * channels;
                buffer = new uint8_t[size];

                snd_pcm_start(handle);

                while (instance->IsEnabled()) {
                    error = snd_pcm_avail(handle);
                    if (error == -EPIPE) {
                        /* EPIPE: Underrun */
                        error = snd_pcm_prepare(handle);
                        if (error < 0) {
                            throw std::runtime_error("Cannot exit from underrun (" + std::string(snd_strerror(error)) + ")");
                        }
                        continue;
                    } else if (error < 0) {
                        throw std::runtime_error("Cannot verify available frames (" + std::string(snd_strerror(error)) + ")");
                    } else if (static_cast<unsigned long>(error) < frames) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(UDP_STREAM_NOP_DELAY));
                        continue;
                    }
                    error = snd_pcm_readi(handle, buffer, frames);
                    if (error == -EPIPE) {
                        /* EPIPE: Overrun */
                        error = snd_pcm_prepare(handle);
                        if (error < 0) {
                            throw std::runtime_error("Cannot exit from overrun (" + std::string(snd_strerror(error)) + ")");
                        }
                        continue;
                    } else if (error < 0) {
                        throw std::runtime_error("Error while reading from device (" + std::string(snd_strerror(error)) + ")");
                    }
                    std::vector<uint8_t> *data = new std::vector<uint8_t>();
                    data->resize(error * (bitsPerChannel >> 3) * channels);
                    std::memcpy(data->data(), buffer, data->size());
                    auto stored = instance->data.exchange(data);
                    if (stored != nullptr) {
                        delete stored;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(std::max(error * 500 / samplingRate, static_cast<uint32_t>(UDP_STREAM_NOP_DELAY))));
                }
            } catch (std::exception &catched) {
                std::string *error = new std::string(catched.what());
                auto stored = instance->error.exchange(error);
                if (stored != nullptr) {
                    delete stored;
                }
            }

            /* if (handle != nullptr) {
                snd_pcm_drain(handle);
                snd_pcm_close(handle);
            } */
            if (buffer != nullptr) {
                delete[] buffer;
            }
        }
        std::atomic<std::vector<uint8_t> *> data;
        std::atomic<std::string *> error;
        std::thread thread;
    };

    OutputDevice::OutputDevice() : Switchable(), data(nullptr), error(nullptr), buffered(0) {
    }

    OutputDevice::~OutputDevice() {
        Disable();
        auto data = this->data.exchange(nullptr);
        if (data != nullptr) {
            delete data;
        }
        auto error = this->error.exchange(nullptr);
        if (error != nullptr) {
            delete error;
        }
    }

    void OutputDevice::Enable(const std::string &device, uint32_t samplingRate, uint8_t channels, uint8_t bitsPerChannel) {
        if (!Switchable::Enable()) {
            return;
        }
        auto data = this->data.exchange(nullptr);
        if (data != nullptr) {
            delete data;
        }
        try {
            thread = std::thread(DeviceThread, this, device, samplingRate, channels, bitsPerChannel);\
        } catch (...) {
            Switchable::Disable();
            throw;
        }
    }

    bool OutputDevice::Disable() {
        static std::mutex access;
        std::lock_guard<std::mutex> lock(access);
        if (Switchable::Disable()) {
            thread.join();
            return true;
        }
        return false;
    }

    std::string OutputDevice::GetError() {
        std::string error;
        auto stored = this->error.exchange(nullptr);
        if (stored != nullptr) {
            error = std::move(*stored);
            delete stored;
        }
        return error;
    }

    void OutputDevice::SetData(const uint8_t *data, std::size_t size) {
        std::vector<uint8_t> *produced = new std::vector<uint8_t>();
        produced->resize(size);
        std::memcpy(produced->data(), data, size);
        auto stored = this->data.exchange(produced);
        if (stored != nullptr) {
            delete stored;
        }
    }

    std::size_t OutputDevice::GetBufferedSamples() const {
        return buffered.load();
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
            unsigned rate = samplingRate; int dir;
            error = snd_pcm_hw_params_set_rate_near(handle, params, &rate, &dir);
            if (error < 0) {
                throw std::runtime_error("Cannot set sampling rate: " + std::to_string(samplingRate) + " (" + std::string(snd_strerror(error)) + ")");
            }
            if (rate != samplingRate) {
                throw std::runtime_error("Cannot set sampling rate: " + std::to_string(samplingRate));
            }

            snd_pcm_uframes_t frames = samplingRate * UDP_STREAM_PERIOD_DURATION / 1000;
            error = snd_pcm_hw_params_set_period_size_near(handle, params, &frames, &dir);
            if (error < 0) {
                throw std::runtime_error("Cannot set period duration: " + std::to_string(UDP_STREAM_PERIOD_DURATION) + " ms (" + std::string(snd_strerror(error)) + ")");
            }
            snd_pcm_uframes_t frameBuffer = frames * UDP_STREAM_BUFFERED_PERIODS;
            error = snd_pcm_hw_params_set_buffer_size_near(handle, params, &frameBuffer);
            if (error < 0) {
                throw std::runtime_error("Cannot set buffer size: " + std::to_string(samplingRate * UDP_STREAM_PERIOD_DURATION * UDP_STREAM_BUFFERED_PERIODS / 1000) + " (" + std::string(snd_strerror(error)) + ")");
            }

            error = snd_pcm_hw_params(handle, params);
            if (error < 0) {
                throw std::runtime_error("Cannot set hardware parameters (" + std::string(snd_strerror(error)) + ")");
            }

            snd_pcm_hw_params_get_period_size(params, &frames, &dir);
            snd_pcm_hw_params_get_buffer_size(params, &frameBuffer);
            std::size_t size = frames * (bitsPerChannel >> 3) * channels;
            buffer = new uint8_t[size];

            bool loaded = false, wait = true;
            std::memset(buffer, 0x00, size);
            std::vector<uint8_t> data;
            while (instance->IsEnabled()) {
                auto stored = instance->data.exchange(nullptr);
                if (stored != nullptr) {
                    std::size_t offset = data.size();
                    data.resize(offset + stored->size());
                    std::memcpy(&data[offset], stored->data(), stored->size());
                    size_t limit = samplingRate * UDP_STREAM_SOUND_DURATION_LIMIT / 1000 * (bitsPerChannel >> 3) * channels;
                    if (data.size() > limit) {
                        data.erase(data.begin(), data.begin() + data.size() - limit);
                    }
                    if (wait && (data.size() >= samplingRate * UDP_STREAM_SOUND_MIN_DURATION / 1000 * (bitsPerChannel >> 3) * channels)) {
                        wait = false;
                    }
                    instance->buffered.store(data.size() / ((bitsPerChannel >> 3) * channels));
                    delete stored;
                }
                bool nop = wait;
                if (!nop) {
                    error = snd_pcm_avail(handle);
                    if (error == -EPIPE) {
                        /* EPIPE: Underrun */
                        error = snd_pcm_prepare(handle);
                        if (error < 0) {
                            throw std::runtime_error("Cannot exit from underrun (" + std::string(snd_strerror(error)) + ")");
                        }
                        continue;
                    } else if (error < 0) {
                        throw std::runtime_error("Cannot verify available frames (" + std::string(snd_strerror(error)) + ")");
                    } else if (static_cast<unsigned long>(error) < frames) {
                        nop = true;
                    }
                }
                if (!nop && !loaded) {
                    if (data.size() < size) {
                        wait = true;
                        nop = true;
                    } else {
                        std::memcpy(buffer, data.data(), size);
                        loaded = true;
                    }
                }
                if (nop) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(std::max(frames * 500 / samplingRate, static_cast<std::size_t>(UDP_STREAM_NOP_DELAY))));
                    continue;
                }
                error = snd_pcm_writei(handle, buffer, frames);
                if (error == -EPIPE) {
                    /* EPIPE: Underrun */
                    error = snd_pcm_prepare(handle);
                    if (error < 0) {
                        throw std::runtime_error("Cannot exit from underrun (" + std::string(snd_strerror(error)) + ")");
                    }
                    continue;
                } else if (error < 0) {
                    throw std::runtime_error("Error while writing to device (" + std::string(snd_strerror(error)) + ")");
                }
                data.erase(data.begin(), data.begin() + error * (bitsPerChannel >> 3) * channels);
                instance->buffered.store(data.size() / ((bitsPerChannel >> 3) * channels));
                loaded = false;
            }
        } catch (std::exception &catched) {
            std::string *error = new std::string(catched.what());
            auto stored = instance->error.exchange(error);
            if (stored != nullptr) {
                delete stored;
            }
        }

        /* if (handle != nullptr) {
            snd_pcm_drain(handle);
            snd_pcm_close(handle);
        } */
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

    class UDPSocket {
    public:
        struct Payload {
            IPAddress address;
            std::vector<uint8_t> data;
        };
        UDPSocket() : sock(-1) { };
        UDPSocket(const UDPSocket &) = delete;
        UDPSocket(UDPSocket &&) = delete;
        virtual ~UDPSocket() {
            Disable();
        }
        UDPSocket &operator=(const UDPSocket &) = delete;
        void Enable(IPAddress::Type type) {
            if (IsEnabled()) {
                throw std::runtime_error("Cannot initialize UDP socket (already enabled)");
            }

            if ((sock = socket(IPAddress::GetFamily(type), SOCK_DGRAM, IPPROTO_UDP)) == -1) {
                throw std::runtime_error("Cannot initialize UDP socket (socket error)");
            }

            int flags = fcntl(sock, F_GETFL, 0);
            if ((flags == -1) || fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
                close(sock);
                throw std::runtime_error("Cannot initialize UDP socket (fcntl error)");
            }
        }
        void Disable() {
            if (!IsEnabled()) {
                return;
            }
            close(sock);
            sock = -1;
        }
        bool IsEnabled() const {
            return (sock != -1);
        }
        void Send(const IPAddress &address, const std::vector<uint8_t> &data) const {
            if (!IsEnabled()) {
                throw std::runtime_error("Cannot send data (socket disabled)");
            }
            socklen_t length = address.GetSockAddrLength();
            while (true) {
                int bytes = sendto(sock, reinterpret_cast<const char *>(data.data()), static_cast<int>(data.size()), 0, address.GetSockAddr(), length);
                if ((bytes != -1) || ((errno != EWOULDBLOCK) && (errno != EAGAIN))) {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(UDP_SERVER_NOP_DELAY));
            }
        }
        Payload Receive() const {
            if (!IsEnabled()) {
                throw std::runtime_error("Cannot receive data (socket disabled)");
            }
            IPAddress address;
            std::vector<uint8_t> data;
            data.resize(UDP_SERVER_PACKET_LENGTH);
            socklen_t length = address.GetSockAddrLength();
            int bytes = recvfrom(sock, reinterpret_cast<char *>(data.data()), static_cast<int>(data.size()), 0, address.GetSockAddr(), &length);
            if (bytes == -1) {
                return { IPAddress(), std::vector<uint8_t>() };
            }
            return { address, std::vector<uint8_t>(data.begin(), data.begin() + bytes) };
        }
    protected:
        int sock;
    };

    class UDPServer : public UDPSocket {
    public:
        void Enable(const std::string &address, uint16_t port) {
            IPAddress ip(address, port);

            UDPSocket::Enable(ip.GetType());

            int enable = 1;
            if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char *>(&enable), sizeof(enable)) == -1) {
                UDPSocket::Disable();
                throw std::runtime_error("Cannot enable server (setsockopt error)");
            }

            if (bind(sock, ip.GetSockAddr(), ip.GetSockAddrLength()) == -1) {
                UDPSocket::Disable();
                throw std::runtime_error("Cannot enable server (bind error)");
            }
        }
    };

    class UDPClient : public UDPSocket {
    public:
        void Enable(const std::string &address, uint16_t port) {
            ip = IPAddress(address, port);
            UDPSocket::Enable(ip.GetType());
        }
        void Send(const std::vector<uint8_t> &stream) const {
            UDPSocket::Send(ip, stream);
        }
        std::vector<uint8_t> Receive() const {
            return UDPSocket::Receive().data;
        }
    private:
        IPAddress ip;
    };

    Service::Service(const DataHandler &dataHandler, const ExceptionHandler &exceptionHandler, const LogHandler &logHandler)
        : Switchable(), dataHandler(dataHandler), exceptionHandler(exceptionHandler), logHandler(logHandler)
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
        if (!Switchable::Enable()) {
            throw std::runtime_error("Cannot enable service (already enabled)");
        }
        try {
            thread = std::thread(ServiceThread, this, address, port, device, samplingRate, channels, bitsPerChannel, dataHandler, exceptionHandler, logHandler);
        } catch (...) {
            Switchable::Disable();
            throw;
        }
    }

    bool Service::Disable()
    {
        static std::mutex access;
        std::lock_guard<std::mutex> lock(access);
        if (Switchable::Disable()) {
            thread.join();
            return true;
        }
        return false;
    }

    void Service::ServiceThread(
        Service *instance,
        const std::string &address,
        uint16_t port,
        const std::string &device,
        uint32_t samplingRate,
        uint8_t channels,
        uint8_t bitsPerChannel,
        const DataHandler &dataHandler,
        const ExceptionHandler &exceptionHandler,
        const LogHandler &logHandler
    )
    {
        UDPServer server;
        InputDevice inputDevice;

        auto handleData = [&](uint8_t *data, std::size_t size) {
            if (dataHandler != nullptr) {
                dataHandler(samplingRate, channels, bitsPerChannel, data, size);
            }
        };

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

        struct Registered {
            IPAddress address;
            std::chrono::time_point<std::chrono::system_clock> timestamp;
        } *registered = nullptr;

        auto handleRequest = [&](const UDPSocket::Payload &request) -> bool {
            std::chrono::time_point<std::chrono::system_clock> current = std::chrono::system_clock::now();
            if (request.data.size() == 1) {
                switch (request.data[0]) {
                case UDP_STREAM_CLIENT_REQUEST_REGISTER:
                    if ((registered != nullptr) && (registered->address == request.address)) {
                        registered->timestamp = current;
                    } else if (registered == nullptr) {
                        registered = new Registered({ request.address, current });
                        printText("Client " + static_cast<std::string>(request.address) + ":" + std::to_string(request.address.GetPort()) + " registered");
                    }
                    break;
                case UDP_STREAM_CLIENT_REQUEST_UNREGISTER:
                    if ((registered != nullptr) && registered->address == request.address) {
                        printText("Client " + static_cast<std::string>(request.address) + ":" + std::to_string(request.address.GetPort()) + " unregistered");
                        delete registered;
                        registered = nullptr;
                    }
                    break;
                default:
                    break;
                }
                return true;
            }
            return false;
        };

        auto handleTimeout = [&]() {
            if ((registered != nullptr) && (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - registered->timestamp).count() > UDP_STREAM_REGISTER_TIMEOUT)) {
                printText("Client " + static_cast<std::string>(registered->address) + ":" + std::to_string(registered->address.GetPort()) + " unregistered");
                delete registered;
                registered = nullptr;
            }
        };

        uint32_t identifier = 0;
        try {
            printText("Starting service on: " + address + ":" + std::to_string(port));
            server.Enable(address, port);

            inputDevice.Enable(device, samplingRate, channels, bitsPerChannel);

            while (instance->IsEnabled()) {
                std::string error = inputDevice.GetError();
                if (!error.empty()) {
                    throw std::runtime_error(error.c_str());
                }
                while (handleRequest(server.Receive()));
                handleTimeout();
                std::vector<uint8_t> *stream = inputDevice.GetData();
                if (stream != nullptr) {
                    if (registered == nullptr) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(UDP_STREAM_NOP_DELAY));
                        delete stream;
                        continue;
                    }
                    handleData(stream->data(), stream->size());
                    while (!stream->empty()) {
                        PacketHeader header = {
                            identifier,
                            samplingRate,
                            channels,
                            bitsPerChannel
                        };
                        std::vector<uint8_t> packet;
                        std::size_t size = std::min(stream->size(), UDP_SERVER_PACKET_LENGTH - sizeof(PacketHeader));
                        packet.resize(sizeof(PacketHeader) + size);
                        std::memcpy(packet.data(), &header, sizeof(PacketHeader));
                        std::memcpy(&packet[sizeof(PacketHeader)], stream->data(), size);
                        server.Send(registered->address, packet);
                        stream->erase(stream->begin(), stream->begin() + size);
                        std::this_thread::sleep_for(std::chrono::milliseconds(std::max(size * 500 / (samplingRate * (bitsPerChannel >> 3) * channels), static_cast<std::size_t>(UDP_STREAM_NOP_DELAY))));
                        identifier++;
                    }
                    delete stream;
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(UDP_STREAM_NOP_DELAY));
                }
            }
        } catch (std::exception &exception) {
            handleException(exception);
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
        if (!Switchable::Enable()) {
            throw std::runtime_error("Cannot enable client (already enabled)");
        }
        try {
            thread = std::thread(ClientThread, this, address, port, device, dataHandler, exceptionHandler);
        } catch (...) {
            Switchable::Disable();
            throw;
        }
    }

    bool Client::Disable()
    {
        static std::mutex access;
        std::lock_guard<std::mutex> lock(access);
        if (Switchable::Disable()) {
            thread.join();
            return true;
        }
        return false;
    }

    void Client::ClientThread(
        Client *instance,
        const std::string &address,
        uint16_t port,
        const std::string &device,
        const DataHandler &dataHandler,
        const ExceptionHandler &exceptionHandler
    )
    {
        UDPClient client;

        auto createRequest = [&](uint8_t type) -> std::vector<uint8_t> {
            std::vector<uint8_t> request;
            request.push_back(type);
            return request;
        };

        bool registered = false;
        try {
            client.Enable(address, port);

            client.Send(createRequest(UDP_STREAM_CLIENT_REQUEST_REGISTER));
            std::chrono::time_point<std::chrono::system_clock> timestamp = std::chrono::system_clock::now();
            registered = true;

            uint32_t last = 0;
            while (instance->IsEnabled()) {
                std::chrono::time_point<std::chrono::system_clock> current = std::chrono::system_clock::now();
                if (std::chrono::duration_cast<std::chrono::milliseconds>(current - timestamp).count() > (UDP_STREAM_REGISTER_TIMEOUT >> 1)) {
                    client.Send(createRequest(UDP_STREAM_CLIENT_REQUEST_REGISTER));
                    timestamp = current;
                }
                std::vector<uint8_t> received = client.Receive();
                if (received.size() > sizeof(PacketHeader)) {
                    PacketHeader *header = reinterpret_cast<PacketHeader *>(received.data());
                    if ((!last || (last < header->identifier)) && (dataHandler != nullptr)) {
                        dataHandler(header->samplingRate, header->channels, header->bitsPerChannel, &received[sizeof(PacketHeader)], received.size() - sizeof(PacketHeader));
                    }
                    last = header->identifier;
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(UDP_STREAM_NOP_DELAY));
                }
            }
        } catch (std::exception &exception) {
            if (exceptionHandler != nullptr) {
                exceptionHandler(exception);
            }
        }
        if (registered) {
            client.Send(createRequest(UDP_STREAM_CLIENT_REQUEST_UNREGISTER));
        }
        client.Disable();
    }
}
