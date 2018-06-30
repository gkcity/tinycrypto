/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   chacha20.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __CHACHA20_H__
#define __CHACHA20_H__

#include <tiny_base.h>
#include <tiny_lor.h>

TINY_BEGIN_DECLS


#define ROTL32(v, n) ((v) << (n)) | ((v) >> (32 - (n)))
#define LE(p) (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) | ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))
#define FROMLE(b, i) (b)[0] = i & 0xFF; (b)[1] = (i >> 8) & 0xFF; (b)[2] = (i >> 16) & 0xFF; (b)[3] = (i >> 24) & 0xFF;

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

typedef struct _ChaCha20
{
    uint32_t    schedule[16];
    uint32_t    keystream[16];
    size_t      available;
} ChaCha20;

// Call this to initialize a ChaCha20, must be called before all other functions
TINY_LOR
void ChaCha20_Initialize(ChaCha20 *thiz, const uint8_t *key, size_t length, const uint8_t *nonce);

//// Call this if you need to process a particular block number
//TINY_LOR
//void ChaCha20_Counter_Set(ChaCha20 *thiz, uint64_t counter);

// Raw keystream for the current block, convert output to uint8_t[] for individual bytes. Counter is incremented upon use
TINY_LOR
void ChaCha20_Block(ChaCha20 *thiz, uint32_t *output);

// Encrypt an arbitrary amount of plaintext, call continuously as needed
TINY_LOR
void ChaCha20_Encrypt(ChaCha20 *thiz, const uint8_t *in, uint8_t *out, size_t length);

// Decrypt an arbitrary amount of ciphertext. Actually, for chacha20, decryption is the same function as encryption
TINY_LOR
void ChaCha20_Decrypt(ChaCha20 *thiz, const uint8_t *in, uint8_t *out, size_t length);


TINY_END_DECLS

#endif /* __CHACHA20_H__ */