cmake_minimum_required(VERSION 3.30)
project(IpQuery)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE})

add_executable(IpQuery main.cpp IpQuery_QQWry.hpp)

file(COPY qqwry.dat DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
