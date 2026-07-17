set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

packing("include" "dog_torch_extra")

file(GLOB_RECURSE resource_h_file RELATIVE "${CMAKE_SOURCE_DIR}/dog_torch_extra" include/*.h)
file(GLOB_RECURSE resource_cpp_file RELATIVE "${CMAKE_SOURCE_DIR}/dog_torch_extra" src/*.cpp)

set(resource_code_file "")
foreach (file ${resource_h_file})
    list(APPEND resource_code_file "${CMAKE_SOURCE_DIR}/dog_torch_extra/${file}")
endforeach ()

foreach (file ${resource_cpp_file})
    list(APPEND resource_code_file "${CMAKE_SOURCE_DIR}/dog_torch_extra/${file}")
endforeach ()

include_directories("${CMAKE_SOURCE_DIR}/dog_torch/include")
include_directories("${CMAKE_SOURCE_DIR}/dog_torch_extra/include")
add_library(static_dog_torch_extra STATIC)
target_sources(static_dog_torch_extra
PRIVATE
    ${resource_code_file}
)
target_link_libraries(static_dog_torch_extra PRIVATE static_dog_torch)

add_library(shared_dog_torch_extra SHARED)
set_target_properties(shared_dog_torch_extra PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/shared_dog_torch_extra")
target_compile_definitions(shared_dog_torch_extra PRIVATE SHARED EXPORT)
target_sources(shared_dog_torch_extra
PRIVATE
    ${resource_code_file}
)
target_link_libraries(shared_dog_torch_extra PRIVATE shared_dog_torch)