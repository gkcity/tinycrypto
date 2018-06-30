/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   chacha20.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include <string.h>
#include "ChaCha20.h"

TINY_LOR
void ChaCha20_Initialize(ChaCha20 *ctx, const uint8_t *key, size_t length, const uint8_t *nonce)
{
    const char *constants = (length == 32) ? "expand 32-byte k" : "expand 16-byte k";

    ctx->schedule[0] = LE(constants + 0);
    ctx->schedule[1] = LE(constants + 4);
    ctx->schedule[2] = LE(constants + 8);
    ctx->schedule[3] = LE(constants + 12);
    ctx->schedule[4] = LE(key + 0);
    ctx->schedule[5] = LE(key + 4);
    ctx->schedule[6] = LE(key + 8);
    ctx->schedule[7] = LE(key + 12);
    ctx->schedule[8] = LE(key + 16 % length);
    ctx->schedule[9] = LE(key + 20 % length);
    ctx->schedule[10] = LE(key + 24 % length);
    ctx->schedule[11] = LE(key + 28 % length);

    //Surprise! This is really a block cipher in CTR mode
    ctx->schedule[12] = 0; //Counter
    ctx->schedule[13] = 0; //Counter
    ctx->schedule[14] = LE(nonce + 0);
    ctx->schedule[15] = LE(nonce + 4);

    ctx->available = 0;
}

//TINY_LOR
//void ChaCha20_Counter_Set(ChaCha20 *ctx, uint64_t counter)
//{
//    ctx->schedule[12] = counter & UINT32_C(0xFFFFFFFF);
//    ctx->schedule[13] = counter >> 32;
//    ctx->available = 0;
//}

#define QUARTERROUND(x, a, b, c, d) \
    x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 8); \
    x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 7);

TINY_LOR
void ChaCha20_Block(ChaCha20 *ctx, uint32_t *output)
{
    uint32_t *const nonce = ctx->schedule + 12; //12 is where the 128 bit counter is
    int i = 10;

    memcpy(output, ctx->schedule, sizeof(ctx->schedule));

    while (i--)
    {
        QUARTERROUND(output, 0, 4, 8, 12)
        QUARTERROUND(output, 1, 5, 9, 13)
        QUARTERROUND(output, 2, 6, 10, 14)
        QUARTERROUND(output, 3, 7, 11, 15)
        QUARTERROUND(output, 0, 5, 10, 15)
        QUARTERROUND(output, 1, 6, 11, 12)
        QUARTERROUND(output, 2, 7, 8, 13)
        QUARTERROUND(output, 3, 4, 9, 14)
    }

    for (i = 0; i < 16; ++i)
    {
        uint32_t result = output[i] + ctx->schedule[i];
        FROMLE((uint8_t *) (output + i), result);
    }

    /*
    Official specs calls for performing a 64 bit increment here, and limit usage to 2^64 blocks.
    However, recommendations for CTR mode in various papers recommend including the nonce component for a 128 bit increment.
    This implementation will remain compatible with the official up to 2^64 blocks, and past that point, the official is not intended to be used.
    This implementation with this change also allows this algorithm to become compatible for a Fortuna-like construct.
    */
    if (!++nonce[0] && !++nonce[1] && !++nonce[2])
    {
        ++nonce[3];
    }
}

TINY_LOR
static void chacha20_xor(uint8_t *keystream, const uint8_t **in, uint8_t **out, size_t length)
{
    uint8_t *end_keystream = keystream + length;

    do
    {
        *(*out)++ = *(*in)++ ^ *keystream++;
    }
    while (keystream < end_keystream);
}

TINY_LOR
void ChaCha20_Encrypt(ChaCha20 *ctx, const uint8_t *in, uint8_t *out, size_t length)
{
    if (length)
    {
        uint8_t *const k = (uint8_t *) ctx->keystream;

        //First, use any buffered keystream from previous calls
        if (ctx->available)
        {
            size_t amount = MIN(length, ctx->available);
            chacha20_xor(k + (sizeof(ctx->keystream) - ctx->available), &in, &out, amount);
            ctx->available -= amount;
            length -= amount;
        }

        //Then, handle new blocks
        while (length)
        {
            size_t amount = MIN(length, sizeof(ctx->keystream));
            ChaCha20_Block(ctx, ctx->keystream);
            chacha20_xor(k, &in, &out, amount);
            length -= amount;
            ctx->available = sizeof(ctx->keystream) - amount;
        }
    }
}

TINY_LOR
void ChaCha20_Decrypt(ChaCha20 *ctx, const uint8_t *in, uint8_t *out, size_t length)
{
    ChaCha20_Encrypt(ctx, in, out, length);
}