cmake_minimum_required(VERSION 2.6)

option(LIEF_DOC "Build LIEF docs" OFF)
option(LIEF_C_API "C API" OFF)
option(LIEF_PYTHON_API "Build LIEF Python API" OFF)
option(LIEF_ENABLE_JSON "Enable JSON-related APIs" OFF)
option(LIEF_EXAMPLES "Build LIEF examples" OFF)
option(LIEF_TESTS "Build LIEF tests" OFF)
option(LIEF_ART "Build LIEF with ART module" OFF)
option(LIEF_DEX "Build LIEF with DEX module" OFF)
option(LIEF_VDEX "Build LIEF with VDEX module" OFF)
option(LIEF_OAT "Build LIEF with OAT module" OFF)
option(LIEF_OPT_MBEDTLS_EXTERNAL "Use external mbedTLS" OFF)

if(MSVC)
    set(LIEF_USE_CRT_RELEASE "MT" CACHE STRING "LIEF CRT option")
endif()

add_subdirectory(vender/LIEF)

include(fib-addon/common.cmake)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/vender/LIEF/include
    ${CMAKE_CURRENT_BINARY_DIR}/vender/LIEF/include
)

add_dependencies(${name} LIB_LIEF)
target_link_libraries(${name} LIB_LIEF)

add_executable(test test/test.c)
set_target_properties(test PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin OUTPUT_NAME test)
