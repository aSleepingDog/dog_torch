#pragma once
//导出符号宏定义
#if defined(EXPORT) && defined(SHARED)//动态导出
    #ifdef _WIN32
        #define CPP_API __declspec(dllexport)
    #else
        #define CPP_API __attribute__((visibility("default")))
    #endif
#elif SHARED//动态导入
    #ifdef _WIN32
        #define CPP_API __declspec(dllimport)
    #else
        #define CPP_API
    #endif
#else//静态
    #define CPP_API
#endif//

#ifdef _WIN32
    #define C_API(type) CPP_API type __cdecl
#else
    #define C_API(type) CPP_API type
#endif