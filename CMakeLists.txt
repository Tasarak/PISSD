cmake_minimum_required(VERSION 3.9)
project(libPISSD)

set(CMAKE_CXX_STANDARD 11)

find_package(Boost COMPONENTS system filesystem REQUIRED)


if (WIN32)
    link_libraries(shlwapi)
endif(WIN32)

link_libraries(cryptopp)
include_directories(cryptopp)
link_directories(cryptopp)

# List of source files
set(libsrc PISSD.cpp PISSD.h)

add_library(PISSD_static STATIC ${libsrc} ${Boost_LIBRARIES})
add_library(PISSD SHARED ${libsrc} ${Boost_LIBRARIES})

target_link_libraries(PISSD ${Boost_LIBRARIES} cryptopp)
target_link_libraries(PISSD_static ${Boost_LIBRARIES} cryptopp)
include_directories(${Boost_INCLUDE_DIR})