cmake_minimum_required(VERSION 3.20)
project(Sniffer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)  
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Threads REQUIRED)

set(SOURCES
    src/main.cpp
    src/packet_analyzer.cpp  
    src/hex_utils.cpp
    src/cli_parser.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_compile_options(${PROJECT_NAME} PRIVATE 
    -Wall -Wextra -Wpedantic -Werror
    $<$<CONFIG:Debug>:-g -O0 -fsanitize=address>  # Добавить AddressSanitizer для Debug
    $<$<CONFIG:Release>:-O3 -DNDEBUG>
)

target_link_libraries(${PROJECT_NAME} PRIVATE 
    Threads::Threads
    $<$<CONFIG:Debug>:-fsanitize=address>  # Линковка санитайзера
)

target_include_directories(${PROJECT_NAME} PRIVATE include)

# Копирование ресурсов
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/docs)
configure_file(${CMAKE_SOURCE_DIR}/docs/header.txt ${CMAKE_BINARY_DIR}/docs/header.txt COPYONLY)

# Тесты
include(CTest)
if(BUILD_TESTING)
    function(add_sniffer_test TEST_NAME SOURCE_FILE)
        add_executable(${TEST_NAME} ${SOURCE_FILE} ${ARGN})
        target_include_directories(${TEST_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)
        target_compile_options(${TEST_NAME} PRIVATE -Wall -Wextra -Wpedantic)
        add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
    endfunction()
    
    add_sniffer_test(dummy_test tests/dummy.cpp)
    add_sniffer_test(format_test tests/format_test.cpp)
    add_sniffer_test(packet_test tests/packet_test.cpp src/packet_analyzer.cpp src/hex_utils.cpp src/cli_parser.cpp)
    add_sniffer_test(cli_parser_test tests/cli_parser_test.cpp src/cli_parser.cpp)
    add_sniffer_test(ipv6_packet_test tests/ipv6_packet_test.cpp src/packet_analyzer.cpp src/hex_utils.cpp src/cli_parser.cpp)
endif()