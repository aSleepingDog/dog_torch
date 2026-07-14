//这里的宏只是编写过程中简写的 最后源文件里不存在
#define CREATE_FUNC(type) \
type(const type& other); \
type& operator=(const type& other); \
type(type&& other) noexcept; \
type& operator=(type&& other) noexcept; \

#define CREATE_DEFAULT_FUNC(type) \
type(const type& other) = default;\
type& operator=(const type& other) = default; \
type(type&& other) noexcept = default; \
type& operator=(type&& other) noexcept = default; \
