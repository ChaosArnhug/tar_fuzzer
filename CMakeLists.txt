cmake_minimum_required(VERSION 3.29)
project(tar_fuzzer C)

set(CMAKE_C_STANDARD 11)

add_executable(tar_fuzzer src/main.c src/utils.c
        src/statstable.c
        src/statstable.h
        src/constants.h
        src/tar.h)

target_sources(tar_fuzzer PRIVATE src/main.c src/utils.c)
