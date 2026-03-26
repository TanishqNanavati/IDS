cmake_minimum_required(VERSION 3.10)

# Project name
project(ids C)

# Use C99
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Include header directory
include_directories(${PROJECT_SOURCE_DIR}/include)

# Source files
set(SOURCES
    src/common.c
    src/parser.c
    src/net_reader.c
    src/rate.c
    main.c
)

# Create executable
add_executable(ids ${SOURCES})

# Optional warnings (recommended)
target_compile_options(ids PRIVATE -Wall -Wextra -Wpedantic)