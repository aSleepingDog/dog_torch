include(../dog_torch/autoLink.cmake)

#feature test
add_executable(test_cmd)
target_sources(test_cmd PRIVATE test_cmd.cpp)
link_dog_torch(test_cmd STATIC)

#math test
set(CMAKE_TOOLCHAIN_FILE E:\\C\\vcpkg_master\\scripts\\buildsystems\\vcpkg.cmake)
find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_library(GMP_LIBRARY NAMES gmp)
find_path(GMPXX_INCLUDE_DIR NAMES gmpxx.h)
find_library(GMPXX_LIBRARY NAMES gmpxx)
add_executable(test_math test_math.cpp)
target_include_directories(test_math PRIVATE ${GMP_INCLUDE_DIR} ${GMPXX_INCLUDE_DIR})
target_link_libraries(test_math PRIVATE ${GMP_LIBRARY} ${GMPXX_LIBRARY})
link_dog_torch(test_math STATIC)

