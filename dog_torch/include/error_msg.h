#pragma once
#include "utils/compile.h"

using dog_torch::utils::from_c_str;
using dog_torch::utils::from_uint64;
using dog_torch::utils::operator+;

////math
//// number.cpp
//constexpr auto ERROR_NUMBER_DIVIDE_BY_ZERO = from_c_str("number: division by zero");
//constexpr auto ERROR_NUMBER_UNEXPECT_RADIX = from_c_str("number: unsupported radix");
//
//constexpr auto ERROR_NUMBER_RADIX_UNEXPECT_CHAR_2 = (from_c_str("number: unexcept char when ") + from_uint64<2>());
//constexpr auto ERROR_NUMBER_RADIX_UNEXPECT_CHAR_8 = (from_c_str("number: unexcept char when ") + from_uint64<8>());
//constexpr auto ERROR_NUMBER_RADIX_UNEXPECT_CHAR_10 = (from_c_str("number: unexcept char when ") + from_uint64<10>());
//constexpr auto ERROR_NUMBER_RADIX_UNEXPECT_CHAR_16 = (from_c_str("number: unexcept char when ") + from_uint64<16>());
//
//constexpr auto ERROR_NUMBER_UNSIGNED_SUBTRACT_LESS = from_c_str("a<b when unsigned numbers subtract");
//
//// region.cpp
//constexpr auto ERROR_REGION_UNEXPECT_CHAR = from_c_str("Unexpected character");
//constexpr auto ERROR_REGION_UNEXPECT_FORMAT = from_c_str("Unexpected format");
//constexpr auto ERROR_REGION_NUMBER_OVERFLOW = from_c_str("Number is too big");
//
////serialize
//// BinaryData.cpp
//constexpr auto ERROR_BINARYDATA_UNEXPECT_CHAR = from_c_str("BinaryData: unexcept char");
//constexpr auto ERROR_BINARYDATA_WRONG_FORMAT = from_c_str("BinaryData: unexcept format");
//constexpr auto ERROR_BINARYDATA_UNEXPECT_TYPE = from_c_str("BinaryData: unexcept type");
//
//// json.cpp
//constexpr auto ERROR_JSON_WRONG_FORMAT = from_c_str("json: Wrong format of in json");
//
////tlv.cpp
//constexpr auto ERROR_TLV_WRONG_TYPE = from_c_str("Value is not ");
//constexpr auto ERROR_TLV_WRONG_TAG = from_c_str("Invalid tag");
//constexpr auto ERROR_TLV_UNSUPPORT_FLOAT = from_c_str("Invalid float tag ");
//
//// asn1.cpp
//constexpr auto ERROR_ASN1_BOOL_LEN = from_c_str("asn1: bool length error");
//constexpr auto ERROR_ASN1_UNKNOWN_TYPE = from_c_str("asn1: unknown type");
//
////crypto
//// hash
////  SHA2.cpp
//constexpr auto ERROR_SHA2_WRONG_EFFECTIVE = from_c_str("SHA2: nosupport effective length");
//constexpr auto ERROR_SHA2_LARGE_DATA_SIZE = from_c_str("SHA2: data size is too large");
//constexpr auto ERROR_SHA2_256_WRONG_BLOCK_SIZE = from_c_str("SHA2:256/224: block size must be 64 bytes");
//constexpr auto ERROR_SHA2_512_WRONG_BLOCK_SIZE = from_c_str("SHA2:512/384: block size must be 128 bytes");
//
////  SM3.cpp
//constexpr auto ERROR_SM3_WRONG_BLOCK_SIZE = from_c_str("SM3: block size must be 64 bytes");
//constexpr auto ERROR_SM3_LARGE_DATA_SIZE = from_c_str("SM3: data size is too large");
//
////  BLAKE.cpp
//constexpr auto ERROR_BLAKE2_OUTPUT_SIZE = from_c_str("BLAKE2: Invalid output size");
//constexpr auto ERROR_BLAKE2_KEY_SIZE = from_c_str("BLAKE2: Invalid key size");
//constexpr auto ERROR_BLAKE2_EFFECTIVE = from_c_str("BLAKE2: only support 64 for BLAKE2b and 32 for BLAKE2s");
//
//// sym
////  stream
////   sym_stream_base.cpp
//constexpr auto ERROR_STREAMCIPHER_SHIFT_TOO_LARGE = from_c_str("StreamCipher: shift is too large than algorithm updata size");
//constexpr auto ERROR_STREAMCIPHER_INIT = from_c_str("StreamCipher: cipher is not initialized, call init() first");
////   algorithm
////    ChaCha.cpp
//constexpr auto ERROR_CHACHA_UNSUPPORTED_ROUND = from_c_str("ChaCha: Unsupported ChaCha round");
////  block
////   sym_block_base.cpp
//constexpr auto ERROR_MODE_SETTING_PADDING = from_c_str("Mode: padding must be set");
//constexpr auto ERROR_BLOCKCIPHER_SETTING_ALGORITHM_MODE = from_c_str("BlockCipher: algorithm or mode must be set");
//constexpr auto ERROR_BLOCKCIPHER_NOT_COMPATIBLE = from_c_str("BlockCipher: algorithm and mode are not compatible");
//constexpr auto ERROR_BLOCKCIPHER_INIT = from_c_str("BlockCipher: cipher is not initialized, call init() first");
////   algorithm
////    Rijndael.cpp
//constexpr auto ERROR_AES_UNSUPPORTED_KEY_SIZE = from_c_str("AES: key size must be 128, 192 or 256");
//constexpr auto ERROR_AES_NOT_EXTEND_KEY_16 = (from_c_str("AES: key size must be bigger than ") + from_uint64<16>() + from_c_str("B"));
//constexpr auto ERROR_AES_NOT_EXTEND_KEY_24 = (from_c_str("AES: key size must be bigger than ") + from_uint64<24>() + from_c_str("B"));
//constexpr auto ERROR_AES_NOT_EXTEND_KEY_32 = (from_c_str("AES: key size must be bigger than ") + from_uint64<32>() + from_c_str("B"));
////    Camellia.cpp
//constexpr auto ERROR_CAMELLIA_UNSUPPORTED_KEY_SIZE = from_c_str("Camellia: key size must be 128, 192 or 256");
//constexpr auto ERROR_CAMELLIA_NOT_EXTEND_KEY_16 = (from_c_str("Camellia: key size must be bigger than ") + from_uint64<16>() + from_c_str("B"));
//constexpr auto ERROR_CAMELLIA_NOT_EXTEND_KEY_24 = (from_c_str("Camellia: key size must be bigger than ") + from_uint64<24>() + from_c_str("B"));
//constexpr auto ERROR_CAMELLIA_NOT_EXTEND_KEY_32 = (from_c_str("Camellia: key size must be bigger than ") + from_uint64<32>() + from_c_str("B"));
////    TwoFish.cpp
//constexpr auto ERROR_TWOFISH_UNSUPPORTED_KEY_SIZE = from_c_str("Twofish: key size must be 128, 192 or 256");
////   padding
////    PKCS7.cpp
//constexpr auto ERROR_PKCS7_WRONG = from_c_str("PKCS7: last block is wrong");
////    ANSIX923.cpp
//constexpr auto ERROR_ANSIX923_WRONG = from_c_str("ANSIX923: last block is wrong");
////    ISO10126.cpp
//constexpr auto ERROR_ISO10126_WRONG = from_c_str("ISO10126: last block is wrong");
////    ISOISO7816_4.cpp
//constexpr auto ERROR_ISO7816_4_WRONG = from_c_str("ISO7816_4: last block is wrong");
////   mode
////    ECB.cpp
//constexpr auto ERROR_ECB_ALLOW_SIZE_OR_PADDING = from_c_str("ECB: plain size must be multiple of block size when NoPadding");
//constexpr auto ERROR_ECB_CRYPT_ALLOW_SIZE = from_c_str("ECB: crypt size must be multiple of block size");
////    CBC.cpp
//constexpr auto ERROR_CBC_ALLOW_SIZE_OR_PADDING = from_c_str("CBC: plain size must be multiple of block size when NoPadding");
//constexpr auto ERROR_CBC_CRYPT_ALLOW_SIZE = from_c_str("CBC: crypt size must be multiple of block size");
////    PCBC.h
//constexpr auto ERROR_PCBC_ALLOW_SIZE_OR_PADDING = from_c_str("PCBC: plain size must be multiple of block size when NoPadding");
//constexpr auto ERROR_PCBC_CRYPT_ALLOW_SIZE = from_c_str("PCBC: crypt size must be multiple of block size");
////    GCM.cpp
//constexpr auto ERROR_GCM_TAG_WRONG = from_c_str("GCM: tag is wrong because of wrong key or plain");
//
//// asym
////  RSA.cpp
//constexpr auto ERROR_RSA_INVALID_KEY = from_c_str("RSA: invalid key");
//constexpr auto ERROR_RSA_TO_LARGE = from_c_str("RSA: input is bigger than key");
////  OAEP.cpp
//constexpr auto ERROR_OAEP_INVALID = from_c_str("OAEP:invalid OAEP padding");
//constexpr auto ERROR_OAEP_RSA = from_c_str("OAEP:only support RSA and key size must big than 512b");
//constexpr auto ERROR_OAEP_TO_LARGE = from_c_str("OAEP:input is bigger than key");

//math
// number.cpp
constexpr auto ERROR_NUMBER_DIVIDE_BY_ZERO = from_c_str("number: 除数不能为0");
constexpr auto ERROR_NUMBER_UNEXPECT_RADIX = from_c_str("number: 不支持的进制");

constexpr auto ERROR_NUMBER_RADIX_UNEXPECT_CHAR_2 = (from_c_str("number: 在") + from_uint64<2>() + from_c_str("进制出现意外字符"));
constexpr auto ERROR_NUMBER_RADIX_UNEXPECT_CHAR_8 = (from_c_str("number: 在") + from_uint64<8>() + from_c_str("进制出现意外字符"));
constexpr auto ERROR_NUMBER_RADIX_UNEXPECT_CHAR_10 = (from_c_str("number: 在") + from_uint64<10>() + from_c_str("进制出现意外字符"));
constexpr auto ERROR_NUMBER_RADIX_UNEXPECT_CHAR_16 = (from_c_str("number: 在") + from_uint64<16>() + from_c_str("进制出现意外字符"));

constexpr auto ERROR_NUMBER_UNSIGNED_SUBTRACT_LESS = from_c_str("无符号减法出现减数大于被减数");

// region.cpp
constexpr auto ERROR_REGION_UNEXPECT_CHAR = from_c_str("region: 意外字符");
constexpr auto ERROR_REGION_UNEXPECT_FORMAT = from_c_str("region: 意外格式");
constexpr auto ERROR_REGION_NUMBER_OVERFLOW = from_c_str("region: 数字过大");

//serialize
// BinaryData.cpp
constexpr auto ERROR_BINARYDATA_UNEXPECT_CHAR = from_c_str("BinaryData: 意外字符");
constexpr auto ERROR_BINARYDATA_WRONG_FORMAT = from_c_str("BinaryData: 意外格式");
constexpr auto ERROR_BINARYDATA_UNEXPECT_TYPE = from_c_str("BinaryData: 意外类型");

// json.cpp
constexpr auto ERROR_JSON_WRONG_FORMAT = from_c_str("json: 格式错误");

//tlv.cpp
constexpr auto ERROR_TLV_WRONG_TYPE = from_c_str("tlv: 内部值不是");
constexpr auto ERROR_TLV_WRONG_TAG = from_c_str("tlv: 无效标签");
constexpr auto ERROR_TLV_UNSUPPORT_FLOAT = from_c_str("tlv: 无效浮点数标签");

// asn1.cpp
constexpr auto ERROR_ASN1_BOOL_LEN = from_c_str("asn1: bool值标签不为1");
constexpr auto ERROR_ASN1_UNKNOWN_TYPE = from_c_str("asn1: 未知标签");

//crypto
// hash
//  SHA2.cpp
constexpr auto ERROR_SHA2_WRONG_EFFECTIVE = from_c_str("SHA2: 不支持的配置长度");
constexpr auto ERROR_SHA2_LARGE_DATA_SIZE = from_c_str("SHA2: 数据过长");
constexpr auto ERROR_SHA2_256_WRONG_BLOCK_SIZE = from_c_str("SHA2:256/224: 单分组大小必须为64B");
constexpr auto ERROR_SHA2_512_WRONG_BLOCK_SIZE = from_c_str("SHA2:512/384: 单分组大小必须为128B");

//  SM3.cpp
constexpr auto ERROR_SM3_WRONG_BLOCK_SIZE = from_c_str("SM3: 单分组大小必须为64B");
constexpr auto ERROR_SM3_LARGE_DATA_SIZE = from_c_str("SM3: 数据过长");

//  BLAKE.cpp
constexpr auto ERROR_BLAKE2_OUTPUT_SIZE = from_c_str("BLAKE2: 无效输出长度");
constexpr auto ERROR_BLAKE2_KEY_SIZE = from_c_str("BLAKE2: 无效密钥长度");
constexpr auto ERROR_BLAKE2_EFFECTIVE = from_c_str("BLAKE2: BLAKE2b仅支持64且BLAKE2s仅支持32");

// sym
//  stream
//   sym_stream_base.cpp
constexpr auto ERROR_STREAMCIPHER_SHIFT_TOO_LARGE = from_c_str("StreamCipher: 偏移量大于单次密钥流长度");
constexpr auto ERROR_STREAMCIPHER_INIT = from_c_str("StreamCipher: 加密器未初始化 先执行init()");
//   algorithm
//    ChaCha.cpp
constexpr auto ERROR_CHACHA_UNSUPPORTED_ROUND = from_c_str("ChaCha: 不支持的轮次值");
//  block
//   sym_block_base.cpp
constexpr auto ERROR_MODE_SETTING_PADDING = from_c_str("Mode: 填充方法未设置");
constexpr auto ERROR_BLOCKCIPHER_SETTING_ALGORITHM_MODE = from_c_str("BlockCipher: 算法未设置");
constexpr auto ERROR_BLOCKCIPHER_NOT_COMPATIBLE = from_c_str("BlockCipher: 算法与模式不匹配");
constexpr auto ERROR_BLOCKCIPHER_INIT = from_c_str("BlockCipher: 加密器未初始化 先执行init()");
//   algorithm
//    Rijndael.cpp
constexpr auto ERROR_AES_UNSUPPORTED_KEY_SIZE = from_c_str("AES: 密钥长度必须为128,192或256");
constexpr auto ERROR_AES_NOT_EXTEND_KEY_16 = (from_c_str("AES: 密钥长度必须大于") + from_uint64<16>() + from_c_str("B"));
constexpr auto ERROR_AES_NOT_EXTEND_KEY_24 = (from_c_str("AES: 密钥长度必须大于") + from_uint64<24>() + from_c_str("B"));
constexpr auto ERROR_AES_NOT_EXTEND_KEY_32 = (from_c_str("AES: 密钥长度必须大于") + from_uint64<32>() + from_c_str("B"));
//    Camellia.cpp
constexpr auto ERROR_CAMELLIA_UNSUPPORTED_KEY_SIZE = from_c_str("Camellia: 密钥长度必须为128,192或256");
constexpr auto ERROR_CAMELLIA_NOT_EXTEND_KEY_16 = (from_c_str("Camellia: 密钥长度必须大于") + from_uint64<16>() + from_c_str("B"));
constexpr auto ERROR_CAMELLIA_NOT_EXTEND_KEY_24 = (from_c_str("Camellia: 密钥长度必须大于") + from_uint64<24>() + from_c_str("B"));
constexpr auto ERROR_CAMELLIA_NOT_EXTEND_KEY_32 = (from_c_str("Camellia: 密钥长度必须大于") + from_uint64<32>() + from_c_str("B"));
//    TwoFish.cpp
constexpr auto ERROR_TWOFISH_UNSUPPORTED_KEY_SIZE = from_c_str("Twofish: 密钥长度必须为128,192或256");
//   padding
//    PKCS7.cpp
constexpr auto ERROR_PKCS7_SIZE_WRONG = from_c_str("PKCS7: 不支持的分组大小");
constexpr auto ERROR_PKCS7_BLOCK_WRONG = from_c_str("PKCS7: 末尾分组格式错误");
//    ANSIX923.cpp
constexpr auto ERROR_ANSIX923_SIZE_WRONG = from_c_str("ANSIX923: 不支持的分组大小");
constexpr auto ERROR_ANSIX923_BLOCK_WRONG = from_c_str("ANSIX923: 末尾分组格式错误");
//    ISO10126.cpp
constexpr auto ERROR_ISO10126_SIZE_WRONG = from_c_str("ISO10126: 不支持的分组大小");
constexpr auto ERROR_ISO10126_BLOCK_WRONG = from_c_str("ISO10126: 末尾分组格式错误");
//    ISOISO7816_4.cpp
constexpr auto ERROR_ISO7816_4_WRONG = from_c_str("ISO7816_4: 末尾分组格式错误");
//   mode
//    ECB.cpp
constexpr auto ERROR_ECB_ALLOW_SIZE_OR_PADDING = from_c_str("ECB: 若不填充则明文长度得是算法单分组的倍数");
constexpr auto ERROR_ECB_CRYPT_ALLOW_SIZE = from_c_str("ECB: 密文长度得是算法单分组的倍数");
//    CBC.cpp
constexpr auto ERROR_CBC_ALLOW_SIZE_OR_PADDING = from_c_str("CBC: 若不填充则明文长度得是算法单分组的倍数");
constexpr auto ERROR_CBC_CRYPT_ALLOW_SIZE = from_c_str("CBC: 密文长度得是算法单分组的倍数");
//    PCBC.h
constexpr auto ERROR_PCBC_ALLOW_SIZE_OR_PADDING = from_c_str("PCBC: 若不填充则明文长度得是算法单分组的倍数");
constexpr auto ERROR_PCBC_CRYPT_ALLOW_SIZE = from_c_str("PCBC: 密文长度得是算法单分组的倍数");
//    GCM.cpp
constexpr auto ERROR_GCM_TAG_WRONG = from_c_str("GCM: 密钥或明文错误导致标签校验失败");

// asym
//  RSA.cpp
constexpr auto ERROR_RSA_INVALID_KEY = from_c_str("RSA: 无效的密钥对");
constexpr auto ERROR_RSA_TO_LARGE = from_c_str("RSA: 输入数据过大");
//  OAEP.cpp
constexpr auto ERROR_OAEP_INVALID = from_c_str("OAEP: 无效参数");
constexpr auto ERROR_OAEP_RSA = from_c_str("OAEP: 仅支持密钥长度大于512b的RSA");
constexpr auto ERROR_OAEP_TO_LARGE = from_c_str("OAEP: 输入数据过大");

using dog_torch::utils::array_to_view;