cmake_minimum_required(VERSION 3.16)
project(dog_torch_napi LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    add_compile_options(/std:c++latest)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-std=c++23)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-std=c++23)
else()

endif()

file(GLOB_RECURSE resource_code_file 
  "${CMAKE_SOURCE_DIR}/../dog_torch/src/*.cpp"
  "${CMAKE_SOURCE_DIR}/../dog_torch/src/*.h"
)
include_directories("${CMAKE_SOURCE_DIR}/../dog_torch/include")
add_library(static_dog_torch STATIC)
target_compile_definitions(static_dog_torch PRIVATE EN_AES_IN)
target_sources(static_dog_torch
PRIVATE
    ${resource_code_file}
)

include_directories("${CMAKE_SOURCE_DIR}/node_modules/node-addon-api")
include_directories("${CMAKE_SOURCE_DIR}/src/include")
include_directories(${CMAKE_JS_INC})

file(GLOB_RECURSE SOURCE_CPP
    "${CMAKE_SOURCE_DIR}/src/*.h"
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
)

add_library(${PROJECT_NAME} SHARED ${SOURCE_CPP} ${CMAKE_JS_SRC})
set_target_properties(${PROJECT_NAME} PROPERTIES 
    PREFIX "" 
    SUFFIX ".node"
)

target_link_libraries(${PROJECT_NAME}
    static_dog_torch
    ${CMAKE_JS_LIB}
)

if(MSVC AND CMAKE_JS_NODELIB_DEF AND CMAKE_JS_NODELIB_TARGET)
  execute_process(COMMAND powershell /def:${CMAKE_JS_NODELIB_DEF} /out:${CMAKE_JS_NODELIB_TARGET} ${CMAKE_STATIC_LINKER_FLAGS})
endif()