#include "BinaryData_wrapper.h"
#include "region_wrapper.h"
#include "crypto_utils_wrapper.h"
#include "crypto_hash_wrapper.h"
#include "crypto_sym_stream_wrapper.h"
#include "crypto_sym_block_wrapper.h"
#include "crypto_sym_wrapper.h"
#include "async_wrapper.h"

Napi::Object Init(Napi::Env env, Napi::Object exports)
{
    exports["BinaryType"] = registerBinaryTypeEnum(env);
    BinaryDataWrapper::registerClass(env, exports);
    BinaryParamsWrapper::registerClass(env, exports);
    NumberIteratorWrapper::registerClass(env, exports);

    Napi::Object crypto = Napi::Object::New(env);
    crypto["ParamType"] = registerCryptoTypeEnum(env);
    ParamInfoWrapper::registerClass(env,crypto);

        Napi::Object crypto_hash = Napi::Object::New(env);
        HashConfigWrapper::registerClass(env,crypto_hash);
        registerHashConfigs(env,crypto_hash);
        HashConfigWrapper::registerClass(env,crypto_hash);
        HashAlgorithmWrapper::registerClass(env,crypto_hash);
        registerHash(env,crypto_hash);
        HashGeneratorWrapper::registerClass(env,crypto_hash);
        crypto["hash"] = crypto_hash;

        Napi::Object crypto_sym = Napi::Object::New(env);
            Napi::Object crypto_sym_stream = Napi::Object::New(env);
                Napi::Object crypto_sym_stream_algorithm = Napi::Object::New(env);
                StreamAlgorithmConfigWrapper::registerClass(env,crypto_sym_stream_algorithm);
                registerSymStreamAllConfig(env,crypto_sym_stream_algorithm);
                StreamAlgorithmWrapper::registerClass(env,crypto_sym_stream_algorithm);
                registerSymStream(env,crypto_sym_stream_algorithm);
                crypto_sym_stream["algorithm"] = crypto_sym_stream_algorithm;
                StreamCipherWrapper::registerClass(env,crypto_sym_stream);
                registerReadStreamCipher(env,crypto_sym_stream);
            crypto_sym["stream"] = crypto_sym_stream;
            
            Napi::Object crypto_sym_block = Napi::Object::New(env);
                Napi::Object crypto_sym_block_alg = Napi::Object::New(env);
                    BlockAlgorithmConfigWrapper::registerClass(env,crypto_sym_block_alg);
                    registerSymBlockAlgorithmConfigAll(env,crypto_sym_block_alg);
                    BlockAlgorithmWrapper::registerClass(env,crypto_sym_block_alg);
                    registerBlockAlgorithm(env,crypto_sym_block_alg);
                crypto_sym_block["algorithm"] = crypto_sym_block_alg;
                Napi::Object crypto_sym_block_padding = Napi::Object::New(env);
                    BlockPaddingWrapper::registerClass(env,crypto_sym_block_padding);
                    registerBlockPadding(env,crypto_sym_block_padding);
                crypto_sym_block["padding"] = crypto_sym_block_padding;
                Napi::Object crypto_sym_block_mode = Napi::Object::New(env);
                    BlockModeConfigWrapper::registerClass(env,crypto_sym_block_mode);
                    registerSymBlockModeConfigAll(env,crypto_sym_block_mode);
                    BlockModeWrapper::registerClass(env,crypto_sym_block_mode);
                    registerBlockMode(env,crypto_sym_block_mode);
                crypto_sym_block["mode"] = crypto_sym_block_mode;
                BlockCipherWrapper::registerClass(env,crypto_sym_block);
                registerReadBlockCipher(env,crypto_sym_block);
            crypto_sym["block"] = crypto_sym_block;
        crypto["sym"] = crypto_sym;
    
    exports["crypto"] = crypto;

    Napi::Object async = Napi::Object::New(env);
    async["Status"] = registerThreadStatusEnum(env);
    async["TaskType"] = registerTaskTypeEnum(env);
    ThreadPoolWrapper::registerClass(env,async);
    exports["async"] = async;

    return exports;
}
NODE_API_MODULE(dog_torch_napi, Init)