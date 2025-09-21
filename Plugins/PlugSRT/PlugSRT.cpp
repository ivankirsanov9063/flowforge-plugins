// PlugSRT.cpp
//
// Рабочий SRT-плагин для VPN-клиента/сервера под Linux.
// - UDP-транспорт через libsrt
// - Шифрование и «авторизация» через SRTO_PASSPHRASE + SRTO_PBKEYLEN=32 (AES-256)
// - Используется stream-API (SRTO_MESSAGEAPI=0), поверх него свой фрейминг:
//     [4 байта big-endian длина][payload]
// - Многопоточность: клиент (uplink/downlink), сервер: accept-поток,
//   по 1 uplink-потоку на клиента и 1 общий downlink-поток (TUN->клиенты).
// - Сервер использует один TUN-интерфейс (через переданные функторы),
//   маршрутизируя пакеты по dst IPv4 (виртуальный IP клиента) -> конкретный сокет.
// - Все ошибки логируются в std::cerr; предусмотрены таймауты для корректной остановки.
//
// Сборка (пример):
//   g++ -std=c++23 -O2 -Wall -Wextra -pthread -fPIC -shared PlugSRT.cpp -o libPlugSRT.so -lsrt
//
// Пакеты:
//   Ubuntu/Debian: sudo apt-get install -y libsrt-dev
//
// Внешний API (C):
//   extern "C" bool Client_Connect(boost::json::object& config) noexcept;
//   extern "C" void Client_Disconnect() noexcept;
//   extern "C" int  Client_Serve(...);
//
//   extern "C" bool Server_Bind(boost::json::object& config) noexcept;
//   extern "C" int  Server_Serve(...);

#include "Plugin.hpp"
#include "Config.hpp"
#include <cstdint>
#include <cstddef>
#include <string>
#include <functional>
#include <atomic>
#include <thread>
#include <vector>
#include <map>
#include <mutex>
#include <unordered_map>
#include <iostream>
#include <sstream>
#include <cstring>
#include <cerrno>
#include <condition_variable>
#include <boost/json/object.hpp>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
#endif
#include <csignal>

#include <srt/srt.h>

// ==== Глобальные настройки шифрования SRT (авторизация через passphrase) ====
static std::string kPassphrase = "flowforge123";
static const int  kKeyLen      = 32; // AES-256

// ==== Общие константы/утилиты ====
static constexpr int    kIOTimeoutMs        = 500;      // таймауты, чтобы проверять working_flag
static constexpr int    kListenBacklog      = 64;
static constexpr size_t kMaxPktSize         = 65535;    // верх пакета L3/TUN
static constexpr size_t kFrameHeaderSize    = 4;        // BE length prefix
static constexpr size_t kMaxFrameSize       = kFrameHeaderSize + kMaxPktSize;
static constexpr int    kSrtLiveMode        = 1;        // SRTT_LIVE

static std::once_flag g_srt_once;

// srt_startup/cleanup — один раз.
static void EnsureSrtStarted()
{
    std::call_once(g_srt_once, []
    {
        if (srt_startup() != 0)
        {
            std::cerr << "[srt] startup failed: " << srt_getlasterror_str() << std::endl;
        }
        std::atexit([] { srt_cleanup(); });
    });
}

static void LogSrtLastError(const char* where)
{
    const int ec = srt_getlasterror(nullptr);
    std::cerr << where << ": SRT error " << ec << " (" << srt_getlasterror_str() << ")\n";
    srt_clearlasterror();
}

static bool SetOpt(SRTSOCKET s, SRT_SOCKOPT opt, const void* val, int len, const char* name)
{
    if (srt_setsockopt(s, 0, opt, val, len) == SRT_ERROR)
    {
        std::cerr << "[srt] setsockopt " << name << " failed: " << srt_getlasterror_str() << std::endl;
        return false;
    }
    return true;
}

// Опции, которые НУЖНО поставить ДО connect/accept (на клиентском сокете/листенере)
static bool SetPreConnectOptions(SRTSOCKET s)
{
    // Stream-API (без message-API)
    int msgapi = 0;
    if (!SetOpt(s, SRTO_MESSAGEAPI, &msgapi, sizeof(msgapi), "MESSAGEAPI")) return false;

    // Живой режим низкой задержки.
    int transtype = kSrtLiveMode; // SRTT_LIVE = 1
    if (!SetOpt(s, SRTO_TRANSTYPE, &transtype, sizeof(transtype), "TRANSTYPE")) return false;

    // Шифрование/«авторизация».
    if (!SetOpt(s, SRTO_PBKEYLEN, &kKeyLen, sizeof(kKeyLen), "PBKEYLEN")) return false;
    if (!SetOpt(s, SRTO_PASSPHRASE, kPassphrase.c_str(), kPassphrase.size(), "PASSPHRASE")) return false;

    // Таймауты I/O.
    int rcvto = kIOTimeoutMs, sndto = kIOTimeoutMs;
    if (!SetOpt(s, SRTO_RCVTIMEO, &rcvto, sizeof(rcvto), "RCVTIMEO")) return false;
    if (!SetOpt(s, SRTO_SNDTIMEO, &sndto, sizeof(sndto), "SNDTIMEO")) return false;

    return true;
}

// Опции, которые можно ставить ПОСЛЕ установления соединения (на accepted сокете)
static bool SetPostConnectOptions(SRTSOCKET s)
{
    int rcvto = kIOTimeoutMs, sndto = kIOTimeoutMs;
    if (!SetOpt(s, SRTO_RCVTIMEO, &rcvto, sizeof(rcvto), "RCVTIMEO")) return false;
    if (!SetOpt(s, SRTO_SNDTIMEO, &sndto, sizeof(sndto), "SNDTIMEO")) return false;
    return true;
}

static bool SetListenerOptions(SRTSOCKET s)
{
    // Всё, что должно быть унаследовано accepted-сокетами, ставим на листенер ДО listen().
    if (!SetPreConnectOptions(s)) return false;

    // Разрешить переиспользование порта.
    int yes = 1;
    if (!SetOpt(s, SRTO_REUSEADDR, &yes, sizeof(yes), "REUSEADDR")) return false;

    return true;
}

// Отправка всех байт в stream-API.
static bool SrtSendAll(SRTSOCKET s, const std::uint8_t* data, std::size_t len)
{
    std::size_t sent = 0;
    while (sent < len)
    {
        const int chunk = srt_send(s, reinterpret_cast<const char*>(data + sent), (int)(len - sent));
        if (chunk == SRT_ERROR)
        {
            const int ec = srt_getlasterror(nullptr);
            if (ec == SRT_ETIMEOUT) continue;
            LogSrtLastError("[srt_send]");
            return false;
        }
        if (chunk == 0)
        {
            std::cerr << "[srt_send] peer closed\n";
            return false;
        }
        sent += (std::size_t)chunk;
    }
    return true;
}

// Чтение ровно len байт или ошибка/EOF.
static bool SrtRecvAll(SRTSOCKET s, std::uint8_t* data, std::size_t len)
{
    std::size_t recvd = 0;
    while (recvd < len)
    {
        const int got = srt_recv(s, reinterpret_cast<char*>(data + recvd), (int)(len - recvd));
        if (got == SRT_ERROR)
        {
            const int ec = srt_getlasterror(nullptr);
            if (ec == SRT_ETIMEOUT) continue;
            LogSrtLastError("[srt_recv]");
            return false;
        }
        if (got == 0)
        {
            std::cerr << "[srt_recv] peer closed\n";
            return false;
        }
        recvd += (std::size_t)got;
    }
    return true;
}

static void BE32_Store(std::uint8_t* p, std::uint32_t v)
{
    p[0] = static_cast<std::uint8_t>((v >> 24) & 0xFF);
    p[1] = static_cast<std::uint8_t>((v >> 16) & 0xFF);
    p[2] = static_cast<std::uint8_t>((v >>  8) & 0xFF);
    p[3] = static_cast<std::uint8_t>( v        & 0xFF);
}

static std::uint32_t BE32_Load(const std::uint8_t* p)
{
    return ( (std::uint32_t)p[0] << 24 ) |
           ( (std::uint32_t)p[1] << 16 ) |
           ( (std::uint32_t)p[2] <<  8 ) |
           ( (std::uint32_t)p[3] );
}

// Отправить один кадр [len][payload].
static bool SendFrame(SRTSOCKET s, const std::uint8_t* buf, std::size_t len)
{
    if (len > kMaxPktSize)
    {
        std::cerr << "[frame] payload too large: " << len << " > " << kMaxPktSize << " (drop)\n";
        return false;
    }

    std::uint8_t hdr[kFrameHeaderSize];
    BE32_Store(hdr, static_cast<std::uint32_t>(len));
    if (!SrtSendAll(s, hdr, sizeof(hdr))) return false;
    if (len == 0) return true;
    return SrtSendAll(s, buf, len);
}

// Принять один кадр в динамический буфер.
static bool RecvFrame(SRTSOCKET s, std::vector<std::uint8_t>& out)
{
    std::uint8_t hdr[kFrameHeaderSize];
    if (!SrtRecvAll(s, hdr, sizeof(hdr))) return false;

    const std::uint32_t len = BE32_Load(hdr);
    if (len > kMaxPktSize)
    {
        // Корректно дочитываем и отбрасываем.
        std::cerr << "[frame] received oversized frame: " << len << " > " << kMaxPktSize << " (drop)\n";
        std::vector<std::uint8_t> sink(4096);
        std::uint32_t left = len;
        while (left > 0)
        {
            const std::size_t take = left > sink.size() ? sink.size() : (std::size_t)left;
            if (!SrtRecvAll(s, sink.data(), take)) return false;
            left -= (std::uint32_t)take;
        }
        return true; // обработано (дроп)
    }

    out.resize(len);
    if (len == 0) return true;
    return SrtRecvAll(s, out.data(), out.size());
}

// Минимальный парсер IPv4 (src/dst).
static bool ParseIPv4SrcDst(const std::uint8_t* data, std::size_t len, std::uint32_t& src, std::uint32_t& dst)
{
    if (len < 20) return false;
    const std::uint8_t ver_ihl = data[0];
    const std::uint8_t version = (ver_ihl >> 4) & 0xF;
    const std::uint8_t ihl     = (ver_ihl & 0xF) * 4;
    if (version != 4) return false;
    if (ihl < 20 || ihl > len) return false;

    std::memcpy(&src, data + 12, 4);
    std::memcpy(&dst, data + 16, 4);
    return true; // src/dst уже в сетевом порядке (BE)
}

static std::string IPv4ToStringBE(std::uint32_t be_addr)
{
    char buf[INET_ADDRSTRLEN] = {0};
    in_addr ia{};
    ia.s_addr = be_addr; // network order
    if (!inet_ntop(AF_INET, &ia, buf, sizeof(buf)))
        return std::string("<bad-ip>");
    return std::string(buf);
}

// ==== Клиентская часть ====
struct ClientState
{
    SRTSOCKET sock = SRT_INVALID_SOCK;
    sockaddr_in server{};
    std::atomic<bool> connected{false};
    std::mutex m;
} g_client;

PLUGIN_API bool Client_Connect(boost::json::object& config) noexcept
{
    int port = Config::RequireInt(config, "port");
    std::string server_ip = Config::RequireString(config, "server");
    kPassphrase = Config::RequireString(config, "password");

    EnsureSrtStarted();

    std::lock_guard<std::mutex> lk(g_client.m);
    if (g_client.connected.load())
    {
        std::cerr << "[client] already connected\n";
        return true;
    }

    g_client.sock = srt_create_socket();
    if (g_client.sock == SRT_INVALID_SOCK)
    {
        LogSrtLastError("[client] srt_create_socket");
        return false;
    }
    if (!SetPreConnectOptions(g_client.sock))
    {
        srt_close(g_client.sock);
        g_client.sock = SRT_INVALID_SOCK;
        return false;
    }

    std::memset(&g_client.server, 0, sizeof(g_client.server));
    g_client.server.sin_family = AF_INET;
    g_client.server.sin_port   = htons(port);
    if (inet_pton(AF_INET, server_ip.c_str(), &g_client.server.sin_addr) != 1)
    {
        std::cerr << "[client] bad server_ip: " << server_ip << "\n";
        srt_close(g_client.sock);
        g_client.sock = SRT_INVALID_SOCK;
        return false;
    }

    if (srt_connect(g_client.sock, (sockaddr*)&g_client.server, sizeof(g_client.server)) == SRT_ERROR)
    {
        LogSrtLastError("[client] srt_connect");
        srt_close(g_client.sock);
        g_client.sock = SRT_INVALID_SOCK;
        return false;
    }

    g_client.connected.store(true);
    std::cerr << "[client] connected to " << server_ip << ":" << port << "\n";
    return true;
}

PLUGIN_API void Client_Disconnect() noexcept
{
    std::lock_guard<std::mutex> lk(g_client.m);
    if (!g_client.connected.load()) return;

    srt_close(g_client.sock);
    g_client.sock = SRT_INVALID_SOCK;
    g_client.connected.store(false);
    std::cerr << "[client] disconnected\n";
}

static void Client_UplinkThread(const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
                                const volatile sig_atomic_t* working_flag,
                                SRTSOCKET sock)
{
    std::vector<std::uint8_t> buf(kMaxPktSize);

    while (*working_flag)
    {
        const ssize_t n = receive_from_net(buf.data(), buf.size());
        if (n < 0)
        {
            std::cerr << "[client] receive_from_net error, continue\n";
            continue;
        }
        if (n == 0) continue;

        if (!SendFrame(sock, buf.data(), (std::size_t)n))
        {
            std::cerr << "[client] uplink send failed (peer closed or error)\n";
            break;
        }
    }
}

static void Client_DownlinkThread(const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
                                  const volatile sig_atomic_t* working_flag,
                                  SRTSOCKET sock)
{
    std::vector<std::uint8_t> frame;

    while (*working_flag)
    {
        if (!RecvFrame(sock, frame))
        {
            std::cerr << "[client] downlink recv failed (peer closed or error)\n";
            break;
        }
        if (frame.empty()) continue;

        std::size_t off = 0;
        while (off < frame.size())
        {
            const ssize_t w = send_to_net(frame.data() + off, frame.size() - off);
            if (w < 0)
            {
                std::cerr << "[client] send_to_net error, drop packet\n";
                break;
            }
            off += (std::size_t)w;
        }
    }
}

PLUGIN_API int Client_Serve(const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
                            const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
                            const volatile sig_atomic_t *working_flag) noexcept
{
    if (!working_flag)
    {
        std::cerr << "[client] working_flag is null\n";
        return -1;
    }

    SRTSOCKET sock;
    {
        std::lock_guard<std::mutex> lk(g_client.m);
        if (!g_client.connected.load())
        {
            std::cerr << "[client] not connected\n";
            return -1;
        }
        sock = g_client.sock;
    }

    std::thread t_up(Client_UplinkThread, std::ref(receive_from_net), working_flag, sock);
    std::thread t_dn(Client_DownlinkThread, std::ref(send_to_net),  working_flag, sock);

    while (*working_flag)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    Client_Disconnect();
    if (t_up.joinable()) t_up.join();
    if (t_dn.joinable()) t_dn.join();

    return 0;
}

// ==== Серверная часть ====
struct ServerState
{
    SRTSOCKET listen_sock = SRT_INVALID_SOCK;

    // dst (виртуальный IP клиента, BE) -> сокет клиента
    std::mutex map_mx;
    std::unordered_map<std::uint32_t, SRTSOCKET> dst_to_sock;

    // Все клиентские сокеты и их uplink-потоки
    std::mutex clients_mx;
    std::vector<SRTSOCKET> client_socks;
    std::vector<std::thread> client_uplink_threads;

    std::atomic<bool> bound{false};
} g_server;

PLUGIN_API bool Server_Bind(boost::json::object& config) noexcept
{
    int port = Config::RequireInt(config, "port");
    kPassphrase = Config::RequireString(config, "password");

    EnsureSrtStarted();

    if (g_server.bound.load())
    {
        std::cerr << "[server] already bound\n";
        return true;
    }

    g_server.listen_sock = srt_create_socket();
    if (g_server.listen_sock == SRT_INVALID_SOCK)
    {
        LogSrtLastError("[server] srt_create_socket");
        return false;
    }
    if (!SetListenerOptions(g_server.listen_sock))
    {
        srt_close(g_server.listen_sock);
        g_server.listen_sock = SRT_INVALID_SOCK;
        return false;
    }

    sockaddr_in sa{};
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port        = htons(port);

    if (srt_bind(g_server.listen_sock, (sockaddr*)&sa, sizeof(sa)) == SRT_ERROR)
    {
        LogSrtLastError("[server] srt_bind");
        srt_close(g_server.listen_sock);
        g_server.listen_sock = SRT_INVALID_SOCK;
        return false;
    }

    if (srt_listen(g_server.listen_sock, kListenBacklog) == SRT_ERROR)
    {
        LogSrtLastError("[server] srt_listen");
        srt_close(g_server.listen_sock);
        g_server.listen_sock = SRT_INVALID_SOCK;
        return false;
    }

    g_server.bound.store(true);
    std::cerr << "[server] listening on *:" << port << "\n";
    return true;
}

static void UnmapSocket(SRTSOCKET cs)
{
    std::lock_guard<std::mutex> lk(g_server.map_mx);
    for (auto it = g_server.dst_to_sock.begin(); it != g_server.dst_to_sock.end(); )
    {
        if (it->second == cs) it = g_server.dst_to_sock.erase(it);
        else ++it;
    }
}

static void Server_ClientUplinkLoop(SRTSOCKET cs,
                                    const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
                                    const volatile sig_atomic_t* working_flag)
{
    std::vector<std::uint8_t> frame;

    // Для accepted сокета ставим только post-connect опции (MESSAGEAPI менять нельзя!)
    (void)SetPostConnectOptions(cs);

    while (*working_flag)
    {
        if (!RecvFrame(cs, frame))
        {
            std::cerr << "[server] client uplink recv failed (close this client)\n";
            break;
        }
        if (frame.empty()) continue;

        // Первое появление IP-адреса клиента — привяжем src -> socket для обратного трафика.
        std::uint32_t src_be = 0, dst_be = 0;
        if (ParseIPv4SrcDst(frame.data(), frame.size(), src_be, dst_be))
        {
            std::lock_guard<std::mutex> lk(g_server.map_mx);
            if (!g_server.dst_to_sock.contains(src_be))
            {
                g_server.dst_to_sock.emplace(src_be, cs);
                std::cerr << "[server] bind client " << IPv4ToStringBE(src_be) << " -> socket " << cs << "\n";
            }
        }

        // Пишем в TUN с обработкой частичных записей.
        std::size_t off = 0;
        while (off < frame.size())
        {
            const ssize_t w = send_to_net(frame.data() + off, frame.size() - off);
            if (w < 0)
            {
                std::cerr << "[server] send_to_net error (drop packet)\n";
                break;
            }
            off += (std::size_t)w;
        }
    }

    UnmapSocket(cs);
    srt_close(cs);
}

static void Server_AcceptThread(const volatile sig_atomic_t* working_flag,
                                const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net)
{
    while (*working_flag)
    {
        sockaddr_storage peer{};
        int peerlen = sizeof(peer);

        SRTSOCKET cs = srt_accept(g_server.listen_sock, (sockaddr*)&peer, &peerlen);
        if (cs == SRT_INVALID_SOCK)
        {
            const int ec = srt_getlasterror(nullptr);
            if (!*working_flag) break;
            std::cerr << "[server] accept failed: " << srt_getlasterror_str() << "\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        {
            std::lock_guard<std::mutex> lk(g_server.clients_mx);
            g_server.client_socks.push_back(cs);
        }

        std::cerr << "[server] client accepted: socket " << cs << "\n";

        // Немедленно запустим uplink-поток для этого клиента.
        std::thread th(Server_ClientUplinkLoop, cs, std::ref(send_to_net), working_flag);
        {
            std::lock_guard<std::mutex> lk(g_server.clients_mx);
            g_server.client_uplink_threads.emplace_back(std::move(th));
        }
    }
}

PLUGIN_API int Server_Serve(const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
                            const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
                            const volatile sig_atomic_t *working_flag) noexcept
{
    if (!working_flag)
    {
        std::cerr << "[server] working_flag is null\n";
        return -1;
    }
    if (!g_server.bound.load())
    {
        std::cerr << "[server] not bound\n";
        return -1;
    }

    // Поток accept — сразу, чтобы принимать новых клиентов.
    std::thread t_accept(Server_AcceptThread, working_flag, std::ref(send_to_net));

    // Один общий downlink-поток (TUN -> конкретный клиент по dst IP).
    std::thread t_down([&receive_from_net, working_flag]()
                       {
                           std::vector<std::uint8_t> buf(kMaxPktSize);

                           while (*working_flag)
                           {
                               const ssize_t n = receive_from_net(buf.data(), buf.size());
                               if (n < 0)
                               {
                                   std::cerr << "[server] receive_from_net error, continue\n";
                                   continue;
                               }
                               if (n == 0) continue;

                               std::uint32_t src_be = 0, dst_be = 0;
                               if (!ParseIPv4SrcDst(buf.data(), (std::size_t)n, src_be, dst_be))
                               {
                                   std::cerr << "[server] non-IPv4 packet from TUN (drop)\n";
                                   continue;
                               }

                               SRTSOCKET cs = SRT_INVALID_SOCK;
                               {
                                   std::lock_guard<std::mutex> lk(g_server.map_mx);
                                   auto it = g_server.dst_to_sock.find(dst_be);
                                   if (it != g_server.dst_to_sock.end())
                                       cs = it->second;
                               }

                               if (cs == SRT_INVALID_SOCK)
                               {
                                   static thread_local int miss_cnt = 0;
                                   if ((++miss_cnt % 64) == 1)
                                   {
                                       std::cerr << "[server] no mapping for dst " << IPv4ToStringBE(dst_be) << " (drop)\n";
                                   }
                                   continue;
                               }

                               if (!SendFrame(cs, buf.data(), (std::size_t)n))
                               {
                                   std::cerr << "[server] downlink send failed to socket " << cs << " (drop)\n";
                                   // При ошибке uplink-поток клиента закроет сокет и размэпит при выходе.
                               }
                           }
                       });

    while (*working_flag)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Остановка: закрыть listen, чтобы прервать accept.
    srt_close(g_server.listen_sock);
    if (t_accept.joinable()) t_accept.join();

    // Закрываем все клиентские сокеты — их uplink-потоки завершатся.
    {
        std::lock_guard<std::mutex> lk(g_server.clients_mx);
        for (SRTSOCKET cs : g_server.client_socks)
            srt_close(cs);
    }

    {
        std::lock_guard<std::mutex> lk(g_server.clients_mx);
        for (auto &t : g_server.client_uplink_threads)
            if (t.joinable()) t.join();
        g_server.client_uplink_threads.clear();
        g_server.client_socks.clear();
    }

    if (t_down.joinable()) t_down.join();

    {
        std::lock_guard<std::mutex> lk(g_server.map_mx);
        g_server.dst_to_sock.clear();
    }

    g_server.bound.store(false);
    g_server.listen_sock = SRT_INVALID_SOCK;

    return 0;
}
