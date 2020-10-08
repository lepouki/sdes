cmake_minimum_required(VERSION 3.13)
project(sdes)

set(CMAKE_CXX_STANDARD 17)

file(GLOB SOURCE_FILES inc/sdes/*.hpp src/main.cpp)
add_executable(sdes ${SOURCE_FILES})

include_directories(inc)
