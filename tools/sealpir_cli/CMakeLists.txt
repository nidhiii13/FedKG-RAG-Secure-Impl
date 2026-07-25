cmake_minimum_required(VERSION 3.16)
project(fedkg_sealpir_cli LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(SEAL 4.0 REQUIRED)

set(SEALPIR_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../external/SealPIR" CACHE PATH "SealPIR source root")
set(SEALPIR_BUILD "${CMAKE_CURRENT_LIST_DIR}/../../build/sealpir" CACHE PATH "SealPIR build root")

add_executable(fedkg-sealpir-roundtrip fedkg_sealpir_roundtrip.cpp)
target_include_directories(
  fedkg-sealpir-roundtrip
  PRIVATE
    "${SEALPIR_ROOT}/src"
)
target_link_libraries(
  fedkg-sealpir-roundtrip
  PRIVATE
    "${SEALPIR_BUILD}/src/libsealpir.a"
    SEAL::seal
)
