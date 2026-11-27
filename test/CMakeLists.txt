include(../dog_torch/autoLink.cmake)

#feature test
add_executable(test_cmd test_cmd.cpp)
link_dog_torch(test_cmd STATIC)

#win default VCPKG_ROOT
set(VCPKG_ROOT "%VCPKG_ROOT%" CACHE STRING "")
message("vcpkg root is ${VCPKG_ROOT}")
set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")

#math test
#using gmp to test
set(GMP_INCLUDE_DIR "${VCPKG_ROOT}/installed/x64-windows-static/include/gmp.h")
set(GMP_LIBRARY "${VCPKG_ROOT}/installed/x64-windows-static/lib/gmp.lib")
set(GMPXX_INCLUDE_DIR "${VCPKG_ROOT}/installed/x64-windows-static/include/gmpxx.h")
set(GMPXX_LIBRARY "${VCPKG_ROOT}/installed/x64-windows-static/lib/gmpxx.lib")
add_executable(test_math test_math.cpp)
target_include_directories(test_math PRIVATE ${GMP_INCLUDE_DIR} ${GMPXX_INCLUDE_DIR})
target_link_libraries(test_math PRIVATE ${GMP_LIBRARY} ${GMPXX_LIBRARY})
link_dog_torch(test_math STATIC)

#SHA2 test
add_executable(test_SHA2 test_SHA2.cpp)
link_dog_torch(test_SHA2 STATIC)

#SM3 test
add_executable(test_SM3 test_SM3.cpp)
link_dog_torch(test_SM3 STATIC)

#BLAKE2 test
add_executable(test_BLAKE2 test_BLAKE2.cpp)
link_dog_torch(test_BLAKE2 STATIC)

#AES test
add_executable(test_AES test_AES.cpp)
link_dog_torch(test_AES STATIC)

#SM4 test
add_executable(test_SM4 test_SM4.cpp)
link_dog_torch(test_SM4 STATIC)

#Camellia test
add_executable(test_Camellia test_Camellia.cpp)
link_dog_torch(test_Camellia STATIC)

#mode test
add_executable(test_mode test_mode.cpp)
link_dog_torch(test_mode STATIC)

#hmac test
add_executable(test_hmac test_hmac.cpp)
link_dog_torch(test_hmac STATIC)

#RSA test
#using openssl to test
set(OPENSSL_ROOT_DIR "${VCPKG_ROOT}/installed/x64-windows-static")
find_package(OpenSSL REQUIRED)
add_executable(test_RSA test_RSA.cpp)
link_dog_torch(test_RSA STATIC)
target_link_libraries(test_RSA PRIVATE OpenSSL::Crypto)
# static OpenSSL on Windows pulls in Winsock (ws2_32) and CryptoAPI (crypt32)
if(WIN32)
    target_link_libraries(test_RSA PRIVATE ws2_32 crypt32 advapi32 user32)
endif()

#speed test
add_executable(test_speed test_speed.cpp)
link_dog_torch(test_speed STATIC)