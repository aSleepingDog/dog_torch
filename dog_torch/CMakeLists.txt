set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

packing("include" "dog_torch")

file(GLOB_RECURSE resource_code_file RELATIVE 
  "${CMAKE_SOURCE_DIR}/../dog_torch/src" *.cpp
  "${CMAKE_SOURCE_DIR}/../dog_torch/src" *.h
)

# macro
# 相关宏
#
# EN_C_API
# 启动C语言API导出 (默认关闭)
# export c style api (default off)
#
# EN_AES_IN
# 启动硬件的AES组件加速(如果不支持则退化成软件实现) (默认开启)
# using hardware AES acceleration like AES-IN (if not supported, fallback to software implementation) (default on)
#
# EN_GCM_IN
# 启动硬件的GCM组件加速(如果不支持则退化成软件实现) (默认关闭)
# using hardware GCM acceleration (if not supported, fallback to software implementation) (default off)


if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-maes -msse4.2)
endif()

include_directories("${CMAKE_SOURCE_DIR}/dog_torch/include")
add_library(static_dog_torch STATIC)
target_compile_definitions(static_dog_torch PRIVATE EN_AES_IN)
target_sources(static_dog_torch
PRIVATE
    ${resource_code_file}
)

add_library(shared_dog_torch SHARED)
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
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