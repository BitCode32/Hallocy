cmake_minimum_required(VERSION 3.10)
project(Hallocy C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(${PROJECT_SOURCE_DIR}/Include)
file(GLOB_RECURSE SRC_FILES "${PROJECT_SOURCE_DIR}/Src/*.c")

add_library(Hallocy STATIC ${SRC_FILES})
add_executable(HallocyApp ${PROJECT_SOURCE_DIR}/Src/Main.c)

target_link_libraries(HallocyApp Hallocy)

if (MSVC)
    target_compile_options(Hallocy PRIVATE /W4 /Zl)
else()
    target_compile_options(Hallocy PRIVATE -mavx512f -mavx512vl)
    target_compile_options(HallocyApp PRIVATE -mavx512f -mavx512vl)
    
    target_compile_options(Hallocy PRIVATE -march=native)
    target_compile_options(HallocyApp PRIVATE -march=native)

    target_compile_options(Hallocy PRIVATE -Wall -Wextra -pedantic)
endif()