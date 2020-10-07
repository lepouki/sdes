cmake_minimum_required(VERSION 3.17)
project(sdes)

set(CMAKE_CXX_STANDARD 17)

add_executable(sdes
        sdes/inc/sdes/sdes.hpp
        sdes/inc/sdes/Encrypt.hpp
        sdes/inc/sdes/Decrypt.hpp
        sdes/inc/sdes/Mappings.hpp
        sdes/src/main.cpp)

include_directories(sdes/inc)
