cmake_minimum_required(VERSION 3.20)

project(Sniffer)

set(CMAKE_CXX_STANDARD 17)              # настройка стандарта проекта (fixed)
set(CMAKE_CXX_STANDARD_REQUIRED ON)     # поддержка стандарта для компиляции
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)   # включаем генерацию compile_commands.json

find_program(CLANG_TIDY_EXE NAMES clang-tidy)
if(CLANG_TIDY_EXE)
    set(CMAKE_CXX_CLANG_TIDY ${CLANG_TIDY_EXE})
endif()
find_program(CPPCHECK_EXE NAMES cppcheck)
if(CPPCHECK_EXE)
    set(CMAKE_CXX_CPPCHECK ${CPPCHECK_EXE};--enable=warning, style,perfomance, portability,--std=c++17; --inline-suppr)
endif()

# исполняемый файл
add_executable(
    Sniffer
    src/main.cpp
)

# флаги компилятора
target_compile_options(Sniffer PRIVATE -Wall -Wextra -Wpedantic)
target_include_directories(Sniffer PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Копируем ресурс с ASCII-заголовком в директорию сборки,
# чтобы при запуске из build/ путь "docs/header.txt" существовал
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/docs)
configure_file(${CMAKE_SOURCE_DIR}/docs/header.txt ${CMAKE_BINARY_DIR}/docs/header.txt COPYONLY)

include(CTest)
if(BUILD_TESTING)
    add_executable(dummy_test tests/dummy.cpp)
    add_test(NAME dummy COMMAND dummy_test)
endif()