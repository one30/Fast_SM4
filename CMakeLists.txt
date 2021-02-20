cmake_minimum_required(VERSION 2.8)
project(bitslice)
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c++11 -O3 -g -m64 -mavx2 -mavx512bw -mavx512f")
# set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -O3 -g  -m64 -mavx2 -mavx512f")

include_directories(./include)
aux_source_directory(./src DIR_SRCS)
aux_source_directory(./test DIR_SRCS)

add_executable(SM4-AVX2-bitslice ./test/main.c ${DIR_SRCS})
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)