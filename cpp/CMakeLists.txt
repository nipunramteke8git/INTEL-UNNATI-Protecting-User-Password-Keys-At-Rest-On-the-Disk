cmake_minimum_required(VERSION 3.10)
project(ProtectingUserPasswordKeys)

set(CMAKE_CXX_STANDARD 11)

find_package(OpenSSL REQUIRED)

add_executable(ProtectingUserPasswordKeys main.cpp)
target_link_libraries(ProtectingUserPasswordKeys OpenSSL::SSL OpenSSL::Crypto)