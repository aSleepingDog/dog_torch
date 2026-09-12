#pragma once
#include "napi_wrapper_utils.h"
#include "BinaryData_wrapper.h"
#include "serialize/tlv.h"
#include "crypto_utils_wrapper.h"
#include "crypto/sym/stream/sym_stream_base.h"
#include "crypto/sym/stream/sym_stream_algorithms.h"
#include "crypto/sym/block/sym_block_algorithms.h"
#include "crypto/sym/block/sym_block_paddings.h"
#include "crypto/sym/block/sym_block_modes.h"
#include "crypto_sym_block_wrapper.h"
#include "crypto_sym_stream_wrapper.h"

Napi::Value readBlockCipher(const Napi::CallbackInfo& info);
Napi::Object registerReadBlockCipher(Napi::Env env, Napi::Object exports);

Napi::Value readStreamCipher(const Napi::CallbackInfo& info);
Napi::Object registerReadStreamCipher(Napi::Env env, Napi::Object exports);