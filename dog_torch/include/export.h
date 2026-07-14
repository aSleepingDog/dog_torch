#pragma once
//导出符号宏定义
#if defined(EXPORT) && defined(SHARED)//动态导出
    #ifdef _WIN32
        #define DOG_TORCH_API __declspec(dllexport)
    #else
        #define DOG_TORCH_API __attribute__((visibility("default")))
    #endif
#elif SHARED//动态导入
    #ifdef _WIN32
        #define DOG_TORCH_API __declspec(dllimport)
    #else
        #define DOG_TORCH_API
    #endif
#else//静态
    #define DOG_TORCH_API
#endif//

#define C_API(type) DOG_TORCH_API type __cdecl