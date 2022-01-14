#include "udp_stream.hpp"
#include <vector>
#include <regex>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>

#ifndef UDP_SERVER_PACKET_LENGTH
#define UDP_SERVER_PACKET_LENGTH 32 * 1024
#endif

#define UDP_SERVER_NOP_DELAY 1000

#define UDP_SERVER_SOCKET int
#define UDP_SERVER_SOCKET_ERROR -1
#define UDP_SERVER_CLOSESOCKET close

#define UDP_STREAM_REGISTER_TIMEOUT 10
#define UDP_STREAM_NOP_DELAY 1000

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
        IPAddress(const std::string &address, Type type = Type::Unknown) : IPAddress() {
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
            } else if (type == Type::Unknown) {
                if (IsCorrect(address, Type::IPv4)) {
                    init(Type::IPv4);
                    resolve = false;
                } else if (IsCorrect(address, Type::IPv6)) {
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

    struct PacketHeader {
        uint32_t identifier;
        uint16_t sampleRate;
        uint8_t channels;
        uint8_t bits;
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
            if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char *>(&enable), sizeof(enable)) == UDP_SERVER_SOCKET_ERROR) {
                close(sock);
                throw std::runtime_error("Cannot enable service (setsockopt error)");
            }

            if (bind(sock, addr.GetSockAddr(), addr.GetSockAddrLength()) == UDP_SERVER_SOCKET_ERROR) {
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
                if (bytes == UDP_SERVER_SOCKET_ERROR) {
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
        uint16_t sampleRate,
        uint8_t channels,
        uint8_t bits
    )
    {
        enabled = true;
        thread = std::thread(ServiceThread, this, address, port, device, sampleRate, channels, bits);
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
        uint16_t sampleRate,
        uint8_t channels,
        uint8_t bits
    ) noexcept {
        ExceptionHandler exceptionHandler;
        LogHandler logHandler;
        UDPServer server;

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
        };
        std::vector<Registered> registered;

        std::thread serverThread([&]() {
            printText("Starting service on: " + address + ":" + std::to_string(port));
            server.SetHandler([&](const IPAddress &address, const std::vector<uint8_t> &input) {
                for (std::size_t i = 0; i < input.size(); i++) {
                    std::vector<uint8_t> status;
                    switch (input.data()[0]) {
                    case UDP_STREAM_CLIENT_REQUEST_REGISTER:
                        {
                            std::lock_guard<std::mutex> lock(access);
                            bool add = true;
                            for (auto element = registered.begin(); element != registered.end();) {
                                if (element->address == address) {
                                    element->timeout = std::time(nullptr) + UDP_STREAM_REGISTER_TIMEOUT;
                                    add = false;
                                    break;
                                }
                                element++;
                            }
                            if (add) {
                                registered.push_back({ address, std::time(nullptr) + UDP_STREAM_REGISTER_TIMEOUT });
                                printText("Client " + static_cast<std::string>(address) + ":" + std::to_string(address.GetPort()) + " registered");
                            }
                        }
                        break;
                    case UDP_STREAM_CLIENT_REQUEST_UNREGISTER:
                        {
                            std::lock_guard<std::mutex> lock(access);
                            for (auto element = registered.begin(); element != registered.end();) {
                                if (element->address == address) {
                                    printText("Client " + static_cast<std::string>(address) + ":" + std::to_string(address.GetPort()) + " unregistered");
                                    element = registered.erase(element);
                                    continue;
                                }
                                element++;
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
            } catch (std::exception &exception) {
                handleException(exception);
                instance->enabled = false;
            }
        });

        while (instance->enabled && !server.IsEnabled()) {
            std::this_thread::sleep_for(std::chrono::microseconds(UDP_STREAM_NOP_DELAY));
        }

        auto handleTimeout = [&]() {
            std::lock_guard<std::mutex> lock(access);
            for (auto element = registered.begin(); element != registered.end();) {
                if (element->timeout < std::time(nullptr)) {
                    printText("Client " + static_cast<std::string>(element->address) + ":" + std::to_string(element->address.GetPort()) + " unregistered");
                    element = registered.erase(element);
                    continue;
                }
                element++;
            }
        };

        uint32_t identifier = 0;
        try {
            while (instance->enabled) {
                handleTimeout();
                std::vector<uint8_t> stream = { 'H', 'e', 'l', 'l', 'o', 0 };
                if (!stream.empty())  {
                    std::vector<Registered> clients;
                    {
                        std::lock_guard<std::mutex> lock(access);
                        clients = registered;
                    }
                    PacketHeader header = {
                        identifier,
                        sampleRate,
                        channels,
                        bits
                    };
                    std::vector<uint8_t> packet;
                    packet.resize(sizeof(PacketHeader) + stream.size());
                    std::memcpy(packet.data(), &header, sizeof(PacketHeader));
                    std::memcpy(&packet.data()[sizeof(PacketHeader)], stream.data(), stream.size());
                    for (Registered &client : clients) {
                        server.Send(client.address, packet);
                    }
                    std::this_thread::sleep_for(std::chrono::microseconds(stream.size() * 1000000 / (sampleRate * channels * (bits >> 3))));
                    identifier++;
                } else {
                    std::this_thread::sleep_for(std::chrono::microseconds(UDP_STREAM_NOP_DELAY));
                }
            }
        } catch (std::exception &exception) {
            handleException(exception);
            instance->enabled = false;
        }
        server.Disable();
        if (serverThread.joinable()) {
            serverThread.join();
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
                    dataHandler(header.sampleRate, header.channels, header.bits, &handlerStream.data()[sizeof(PacketHeader)], handlerStream.size() - sizeof(PacketHeader));
                } else {
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
                } else {
                    std::this_thread::sleep_for(std::chrono::microseconds(UDP_STREAM_NOP_DELAY));
                }
            }
        } catch (std::exception &exception) {
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
