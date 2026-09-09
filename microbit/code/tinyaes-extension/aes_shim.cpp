// ============================================================
//  tiny-AES-c wrapped as a MakeCode (PXT/CODAL) C++ extension.
//  Exposes AES-128 to the blocks / TypeScript layer.
//
//  Buffers are PXT `Buffer` objects: read/write bytes via
//  ->data (uint8_t*) and ->length (int). AES here works IN PLACE
//  on a 16-byte block, exactly like tiny-AES-c.
//
//  Requires aes.h and aes.cpp (tiny-AES-c's aes.c, renamed .cpp)
//  in the same extension. tiny-AES-c defaults to AES-128 with
//  ECB/CBC/CTR enabled, so no config edits are needed.
// ============================================================
#include "pxt.h"
#include "aes.h"

using namespace pxt;

namespace tinyAES {

    //% blockId=tinyaes_ecb_encrypt block="AES128 encrypt block %block| with key %key"
    void ecbEncrypt(Buffer block, Buffer key) {
        if (!block || !key || block->length < 16 || key->length < 16) return;
        struct AES_ctx ctx;
        AES_init_ctx(&ctx, key->data);
        AES_ECB_encrypt(&ctx, block->data);          // 16 bytes, in place
    }

    //% blockId=tinyaes_ecb_decrypt block="AES128 decrypt block %block| with key %key"
    void ecbDecrypt(Buffer block, Buffer key) {
        if (!block || !key || block->length < 16 || key->length < 16) return;
        struct AES_ctx ctx;
        AES_init_ctx(&ctx, key->data);
        AES_ECB_decrypt(&ctx, block->data);
    }

    //% blockId=tinyaes_ctr block="AES128 CTR crypt %buf| with key %key| iv %iv"
    void ctrCrypt(Buffer buf, Buffer key, Buffer iv) {
        if (!buf || !key || !iv || key->length < 16 || iv->length < 16) return;
        struct AES_ctx ctx;
        AES_init_ctx_iv(&ctx, key->data, iv->data);
        AES_CTR_xcrypt_buffer(&ctx, buf->data, buf->length);   // any length, in place
    }
}
