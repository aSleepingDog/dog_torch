cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# set(CMAKE_PREFIX_PATH cmake "E:\\C\\vcpkg_master\\installed\\x64-windows")

if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    add_compile_options(/utf-8)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
else()

endif()

project("dog_torch" VERSION 2.0 DESCRIPTION "A simple C++ library for crypto and other utils written by dog")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binary)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/shared)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/static)

#packing header files for visual studio
function(packing PATH ROOT)
    file(GLOB DIR RELATIVE "${CMAKE_SOURCE_DIR}/${ROOT}/${PATH}" ${PATH}/*)
    foreach(ITEM ${DIR})
        if(IS_DIRECTORY "${CMAKE_SOURCE_DIR}/${ROOT}/${PATH}/${ITEM}")
            packing("${PATH}/${ITEM}" "${ROOT}")
        else()
            list(APPEND FILES "${PATH}/${ITEM}")
        endif()
    endforeach(ITEM)
    string(REPLACE "include" "" PATH ${PATH})
    if(NOT PATH STREQUAL "")
        string(REPLACE "/" "\\\\" PATH ${PATH})
    endif()
    source_group("Header Files\\\\${PATH}" FILES ${FILES})
    # message("source_group(Header Files\\\\${PATH} FILES ${FILES})")
endfunction(packing PATH ROOT)

add_subdirectory(dog_torch)
add_subdirectory(cmd_application)
add_subdirectory(test)