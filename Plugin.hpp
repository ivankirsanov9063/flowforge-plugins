#pragma once
#include <cstdint>
#include <cstddef>
#include <functional>
#include <string>
#include <sys/types.h>
#include <csignal>
#include <boost/json/object.hpp>

#ifdef _WIN32

#include <BaseTsd.h>
#define ssize_t SSIZE_T

#endif

#if defined(_WIN32)
#define PLUGIN_API extern "C" __declspec(dllexport)
#else
#define PLUGIN_API extern "C"
#endif

PLUGIN_API bool Client_Connect(boost::json::object& config) noexcept;
PLUGIN_API void Client_Disconnect() noexcept;
PLUGIN_API int  Client_Serve(const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
                  const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
                  const volatile sig_atomic_t *working_flag) noexcept;

PLUGIN_API bool Server_Bind(boost::json::object& config) noexcept;
PLUGIN_API int  Server_Serve(const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
                  const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
                  const volatile sig_atomic_t *working_flag) noexcept;
