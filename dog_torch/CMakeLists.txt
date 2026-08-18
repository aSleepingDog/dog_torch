set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

packing("include" "dog_torch")

file(GLOB_RECURSE resource_code_file RELATIVE 
  "${CMAKE_SOURCE_DIR}/../dog_torch/src" *.cpp
)

#EN_AES_IN
#enable AES IN on supported CPU
#在支持AES的CPU上启用AES IN

include_directories("${CMAKE_SOURCE_DIR}/dog_torch/include")
add_library(static_dog_torch STATIC)
target_compile_definitions(static_dog_torch PRIVATE EN_AES_IN)
target_sources(static_dog_torch
PRIVATE
    ${resource_code_file}
)

add_library(shared_dog_torch SHARED)
if(MSVC)
    #ignore warning 4251 4275
    #忽略警告4251 4275
    target_compile_options(shared_dog_torch PRIVATE /wd4251 /wd4275)
endif()
set_target_properties(shared_dog_torch PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/shared_dog_torch")
target_compile_definitions(shared_dog_torch PRIVATE SHARED EXPORT)
target_compile_definitions(shared_dog_torch PRIVATE EN_AES_IN)
target_sources(shared_dog_torch
PRIVATE
    ${resource_code_file}
)