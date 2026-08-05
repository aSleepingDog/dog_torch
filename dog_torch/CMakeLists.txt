set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

packing("include" "dog_torch")

file(GLOB_RECURSE resource_h_file RELATIVE "${CMAKE_SOURCE_DIR}/dog_torch" include/*.h)
file(GLOB_RECURSE resource_cpp_file RELATIVE "${CMAKE_SOURCE_DIR}/dog_torch" src/*.cpp)

set(resource_code_file "")
foreach (file ${resource_h_file})
    list(APPEND resource_code_file "${CMAKE_SOURCE_DIR}/dog_torch/${file}")
endforeach ()

foreach (file ${resource_cpp_file})
    list(APPEND resource_code_file "${CMAKE_SOURCE_DIR}/dog_torch/${file}")
endforeach ()

include_directories("${CMAKE_SOURCE_DIR}/dog_torch/include")
add_library(static_dog_torch STATIC)
#enable AES IN on supported CPU
#在支持AES的CPU上启用AES IN
target_compile_definitions(static_dog_torch PRIVATE EN_AES_IN)
target_sources(static_dog_torch
PRIVATE
    ${resource_code_file}
)

add_library(shared_dog_torch SHARED)
set_target_properties(shared_dog_torch PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/shared_dog_torch")
target_compile_definitions(shared_dog_torch PRIVATE SHARED EXPORT)
target_compile_definitions(shared_dog_torch PRIVATE EN_AES_IN)
target_sources(shared_dog_torch
PRIVATE
    ${resource_code_file}
)