# dog_torch简单的密码学库

一个用于密码学的C++第三方库，还有一些其他的工具封装

## 支持算法

### 散列函数

```
SHA2
SM3
BLAKE2
```

### 对称加密

#### 算法

```
AES
SM4
Cameilla
TwoFish
```

#### 填充

```
PKCS7
ZERO
ANSIX923
ISO7816.4
ISO10126
```

#### 工作模式

```
ECB
CBC
PCBC
CFB
OFB
CTR
GCM
```

### 流加密

```
ChaCha
```

### 非对称加密

```
RSA
```

### 消息认证码

```
HMAC
```

### 密钥派生

```
HKDF
```

## 其他内容

```
部分Math库
封装的二进制BinaryData
Json
自定义的tlv
部分asn1
线程池
```

## 使用方法

本项目采用C++20标准，CMake构建，使用下面的命令进行编译

```shell
git clone https://github.com/aSleepingDog/dog_torch.git
cd dog_torch
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

使用下列命令链接

```CMake
include(dog_torch/autoLink.cmake)
add_executable(your_project)
target_sources(your_project PRIVATE your_project.cpp)
#使用此函数静态链接
link_dog_torch(your_project STATIC)
#使用此函数动态链接
link_dog_torch(your_project SHARED)
#静态和动态仅需要选择一个即可
```

### 使用示例

#### 封装数据

```cpp
#include "serialize/serialize.h"//include BinaryData json tlv asn1

int main()
{
    using dog_torch::serialize::BinaryData;
    //input 输入
    BinaryData data0{"hello world",BinaryData::Type::UTF8};
    BinaryData data1{"303132333435",BinaryData::Type::HEX};
    BinaryData data1{"010101011101",BinaryData::Type::Binary};
    BinaryData data1{"abcdabcdabc=",BinaryData::Type::Base64};
    //output 输出
    data0.to_string();//to utf8 string 转换为UTF8
    data1.to_bin_string();//to binary string 转换为二进制字符串
    data2.to_hex_string(true);//to hex string 转换为十六进制字符串，true表示大写
    data3.to_base64_string();//to base64 string 转换为base64字符串
    //Other operator of BinaryData is similar to std::vector<unsigned char>
    //其他BinaryData操作和std::vector<unsigned char>类似
}
```

#### 散列函数

```cpp
#include "crypto\hash\hash_algorithms.h"//include all hash function

int main()
{
    using dog_torch::serialize::BinaryData;
    BinaryData data0{"hello world",BinaryData::Type::UTF8};

    using dog_torch::crypto::hash::algorithm::SHA2;   //class
    using dog_torch::crypto::hash::algorithm::create; //factory function
    using dog_torch::crypto::hash::Generator;
    /**
     * can using
     * using namespace dog_torch::crypto::hash;
     * to import most of identifiers. but may cause name conflict
     * 可以使用
     * using namespace dog_torch::crypto::hash;
     * 来引入大部分标识符 但是可能会导致命名冲突
     */
  
    auto alg0 = SHA2(256);//support 224 256 384 512 支持224 256 384 512
    auto alg_p = create("SHA2",256,{});
    //try to create a hash algorithm. return std::unique_ptr when success or nullptr when fail
    //尝试创建一个散列算法，成功返回std::unique_ptr 失败返回nullptr

    Generator gen0(alg0);

    /**
     * must call init() to initialize the generator before every calculate
     * 在每次散列计算之前必须调用init()来初始化生成器
     */
    gen0.init();

    BinaryData hash0 = gen0.calculate(data0);//calculate hash value计算散列值
}
```

#### 对称加密

```cpp
#include "crypto\sym\block\sym_block_algorithms.h"
#include "crypto\sym\block\sym_block_paddings.h"
#include "crypto\sym\block\sym_block_modes.h"

int main()
{
    using dog_torch::serialize::BinaryData;
    BinaryData plain{"hello world",BinaryData::Type::UTF8};
    BinaryData key{"0123456789ABCDEF",BinaryData::Type::UTF8};

    using dog_torch::crypto::sym::block::algorithm::AES;
    using algorithm_create = dog_torch::crypto::sym::block::algorithm::create;

    using dog_torch::crypto::sym::block::padding::PKCS7;
    using padding_create = dog_torch::crypto::sym::block::padding::create;

    using dog_torch::crypto::sym::block::mode::ECB;
    using mode_create = dog_torch::crypto::sym::block::mode::create;

    using dog_torch::crypto::sym::block::BlockCipher;

    auto alg0 = AES(256);//support 128 192 256
    auto alg_p = algorithm_create("AES",128,128);

    auto pad0 = PKCS7();//support 128 192 256
    auto pad_p = padding_create("PKCS7");

    auto mode0 = ECB(pad0);
    auto mode_p = mode_create("ECB",pad_p,{});

    BlockCipher cipher0(alg0,mode0);

    /**
     * must set key before every encrypt and decrypt
     * must call init() to initialize the cipher before every encrypt and decrypt
     * may throw some exception when invalid params or invalid key
     * 必须在每次加解密之前设置密钥
     * 必须在每次加解密之前调用init()来初始化加密器
     * 当参数无效或密钥无效时可能会抛出异常
     */
    cipher0.set_key(key)
    cipher0.init();

    BinaryData crypt = cipher0.encrypt(plain);//encrypt 加密

    BinaryData plaio = cipher0.decrypt(crypt);//decrypt 解密
}
```

其他使用方法等我更新吧……