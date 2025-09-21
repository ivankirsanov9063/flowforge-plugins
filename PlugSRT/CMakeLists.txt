cmake_minimum_required(VERSION 3.18)
project(PlugSRT LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Threads REQUIRED)

find_package(OpenSSL REQUIRED)

# --- libsrt detection (prefer pkg-config). Create INTERFACE imported target ---
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(SRT QUIET srt)
endif()

if(SRT_FOUND)
    add_library(SRT::SRT INTERFACE IMPORTED)
    set_target_properties(SRT::SRT PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${SRT_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES     "${SRT_LIBRARIES};${SRT_LINK_LIBRARIES}"
            INTERFACE_LINK_OPTIONS       "${SRT_LDFLAGS_OTHER}"
            INTERFACE_LINK_DIRECTORIES   "${SRT_LIBRARY_DIRS}"
    )
else()
    # Fallback: manual discovery (Ubuntu/Fedora/macOS)
    find_path(SRT_INCLUDE_DIR
            NAMES srt/srt.h
            PATHS /usr/include /usr/local/include /opt/homebrew/include /opt/local/include
    )
    find_library(SRT_LIBRARY
            NAMES srt
            PATHS /usr/lib /usr/local/lib /opt/homebrew/lib /opt/local/lib
    )
    if(NOT SRT_INCLUDE_DIR OR NOT SRT_LIBRARY)
        message(FATAL_ERROR
                "libsrt not found. Install dev package (Ubuntu: 'sudo apt install libsrt-dev', "
                "Fedora: 'sudo dnf install srt-devel'), or provide pkg-config.")
    endif()

    add_library(SRT::SRT INTERFACE IMPORTED)
    set_target_properties(SRT::SRT PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${SRT_INCLUDE_DIR}"
            INTERFACE_LINK_LIBRARIES      "${SRT_LIBRARY}"
    )
endif()

add_library(PlugSRT SHARED
        PlugSRT.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../Config.cpp)

# Если нужен общий инклуд корня проекта
target_include_directories(PlugSRT PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)

# Можно убрать, если не используешь boost::asio
target_compile_definitions(PlugSRT PRIVATE BOOST_ASIO_NO_DEPRECATED)

target_link_libraries(PlugSRT PRIVATE
        OpenSSL::Crypto
        OpenSSL::SSL
        SRT::SRT
        Threads::Threads
)

# Если pkg-config дал нестандартные пути к либам — добавим их
if(SRT_FOUND AND SRT_LIBRARY_DIRS)
    target_link_directories(PlugSRT PRIVATE ${SRT_LIBRARY_DIRS})
endif()

if(WIN32)
    target_link_libraries(PlugSRT PRIVATE ws2_32 Crypt32 Bcrypt)
else()
    if(APPLE)
        target_link_options(PlugSRT PRIVATE "-Wl,-undefined,error")
    else()
        target_link_options(PlugSRT PRIVATE "-Wl,--no-undefined" "-Wl,-z,defs")
    endif()
endif()

set_target_properties(PlugSRT PROPERTIES OUTPUT_NAME PlugSRT)
