cmake_minimum_required(VERSION 3.13)
project(sdes)

set(CMAKE_CXX_STANDARD 17)

file(GLOB_RECURSE SOURCE_FILES inc/*.hpp src/*.cpp)
add_executable(sdes ${SOURCE_FILES})

include_directories(inc)
