cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 23)

#static
include_directories("${CMAKE_SOURCE_DIR}/dog_torch/include")
add_executable(cmd)
set_target_properties(cmd PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cmd")
target_sources(cmd
    PRIVATE
        cmd.cpp
)
target_link_libraries(cmd PRIVATE static_dog_torch)

#shared
#include_directories("${CMAKE_SOURCE_DIR}/dog_torch/include")
#add_executable(cmd)
#set_target_properties(cmd PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cmd")
#target_compile_definitions(cmd PRIVATE SHARED)
#target_sources(cmd
#    PRIVATE
#        cmd.cpp
#)
#target_link_libraries(cmd PRIVATE shared_dog_torch)

function(add_dog_torch PROJECT TYPE)
    include_directories("${CMAKE_SOURCE_DIR}/dog_torch/include")
    if(${TYPE} STREQUAL "STATIC")
        target_link_libraries(${PROJECT} PRIVATE static_dog_torch)
    elseif(${TYPE} STREQUAL "SHARED")
        target_compile_definitions(${PROJECT} PRIVATE SHARED)
        target_link_libraries(${PROJECT} PRIVATE shared_dog_torch)
    endif()
endfunction(add_dog_torch PROJECT TYPE)
