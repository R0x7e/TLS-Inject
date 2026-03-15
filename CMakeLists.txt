cmake_minimum_required(VERSION 3.10)
project(TLS_Injector)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXE_LINKER_FLAGS "-static")

add_executable(target target.cpp)
add_executable(target_tls target_tls.cpp)
add_executable(injector injector.cpp)
