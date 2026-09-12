#
# add dog_torch as import library
# 添加dog_torch作为导入库
# @Param PROJECT PROJECT_NAME 项目名
# @Param TYPE SHARED|STATIC SHARED为动态库 STATIC为静态库
#
function(link_dog_torch PROJECT TYPE)
    include_directories("${CMAKE_SOURCE_DIR}/dog_torch/include")
    if(${TYPE} STREQUAL "STATIC")
        target_link_libraries(${PROJECT} PRIVATE static_dog_torch)
    elseif(${TYPE} STREQUAL "SHARED")
        target_compile_definitions(${PROJECT} PRIVATE SHARED)
        target_link_libraries(${PROJECT} PRIVATE shared_dog_torch)
    endif()
endfunction(link_dog_torch PROJECT TYPE)