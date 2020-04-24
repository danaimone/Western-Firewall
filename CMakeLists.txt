cmake_minimum_required(VERSION 3.10)
project(wfw)

set(CMAKE_CXX_STANDARD 14)

include_directories(src)
include_directories(tests)

add_executable(wfw
        src/conf.c
        src/conf.h
        src/hash.c
        src/hash.h
        src/wfw.c
        src/wfw.cfg
        tests/cfg_test.c
        tests/ht_test.c)