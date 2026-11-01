cmake_minimum_required(VERSION 3.16)
project(ca_openssl LANGUAGES C)

find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)

add_library(cipher_cores STATIC speck128.c trivium.c)
target_compile_options(cipher_cores PRIVATE -Wall -Wextra -Wpedantic)
set_target_properties(cipher_cores PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(ca MODULE provider.c provider_cipher.c)
target_link_libraries(ca PRIVATE cipher_cores OpenSSL::Crypto)
target_compile_options(ca PRIVATE -Wall -Wextra -Wpedantic)
set_target_properties(ca PROPERTIES PREFIX "")
