cmake_minimum_required(VERSION 3.13)
project(sdes)

set(CMAKE_CXX_STANDARD 17)

add_executable(sdes
        inc/sdes/sdes.hpp
        inc/sdes/Mappings.hpp
        src/main.cpp inc/sdes/MessageOperations.hpp)

include_directories(inc)
