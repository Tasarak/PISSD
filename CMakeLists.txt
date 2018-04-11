cmake_minimum_required(VERSION 3.9)
project(libPISSD)

set(CMAKE_CXX_STANDARD 11)

find_package(Boost COMPONENTS system filesystem REQUIRED)


if (WIN32)
    link_libraries(shlwapi)
endif(WIN32)

link_libraries(cryptopp)

# List of source files
set(libsrc PISSD.cpp PISSD.h)

add_library(PISSD_static STATIC ${libsrc})
add_library(PISSD SHARED ${libsrc})

include_directories(${Boost_INCLUDE_DIR})