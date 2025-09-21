cmake_minimum_required(VERSION 3.18)

project(Plugins LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(
            -Wall -Wextra -Wpedantic
            -Wconversion -Wsign-conversion
            -Wshadow -Wformat=2
    )
endif()

# ---- Boost.Json для всех поддиректорий ----
find_package(Boost REQUIRED COMPONENTS json)

# На старых сборках FindBoost может не создавать целевую Boost::json.
# Создадим интерфейсную цель как fallback (json — заголовочная библиотека).
if(NOT TARGET Boost::json)
    add_library(Boost::json INTERFACE IMPORTED)
    target_include_directories(Boost::json INTERFACE ${Boost_INCLUDE_DIRS})
endif()

# Применяем ко всем целям, создаваемым ниже (включая add_subdirectory).
link_libraries(Boost::json)
# -------------------------------------------

add_subdirectory(PlugSRT)

install(DIRECTORY DESTINATION bin)
