cmake_minimum_required(VERSION 3.5)
project(mod_owa)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    .gitignore
    README.md)

add_executable(mod_owa ${SOURCE_FILES})