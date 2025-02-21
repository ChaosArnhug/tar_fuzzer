cmake_minimum_required(VERSION 3.29)
project(tar_fuzzer C)

set(CMAKE_C_STANDARD 11)

add_executable(fuzzer src/main.c src/help.c
        src/help.h
        src/constants.h
        src/statstable.h)

target_sources(fuzzer PRIVATE src/main.c src/help.c src/statstable.c)
