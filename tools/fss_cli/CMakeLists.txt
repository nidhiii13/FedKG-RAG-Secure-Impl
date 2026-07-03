cmake_minimum_required(VERSION 3.22)
project(fedkg_fss_cli LANGUAGES CXX CUDA)

set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --std=c++20")

find_package(OpenSSL REQUIRED)

add_library(fss INTERFACE)
target_include_directories(fss INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}/compat
  ${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/myl7-fss/include
)
add_executable(fedkg-fss-cli main.cu)
target_link_libraries(fedkg-fss-cli PRIVATE fss OpenSSL::Crypto)
