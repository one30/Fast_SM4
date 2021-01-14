cmake_minimum_required(VERSION 2.8)
project(bitslice)
# set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c++11 -O2  -Wall -m64 -mavx2")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -O0 -g  -m64 -mavx2")

include_directories(./include)
aux_source_directory(./src DIR_SRCS)
aux_source_directory(./test DIR_SRCS)

add_executable(SM4-AVX2-bitslice ./test/main.c ${DIR_SRCS})
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)