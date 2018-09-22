/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   sha512.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __SHA512_H__
#define __SHA512_H__

#include <tiny_base.h>
#include <tiny_lor.h>
#include "common/tiny_crypto_api.h"

TINY_BEGIN_DECLS


#define SHA512_DIGEST_SIZE ( 512 / 8)
#define SHA512_BLOCK_SIZE  (1024 / 8)

typedef struct
{
    unsigned int tot_len;
    unsigned int len;
    unsigned char block[2 * SHA512_BLOCK_SIZE];
    uint64_t h[8];
} sha512_ctx;

TINY_CRYPTO_API
TINY_LOR
void sha512_init(sha512_ctx *ctx);

TINY_CRYPTO_API
TINY_LOR
void sha512_update(sha512_ctx *ctx, const unsigned char *message, unsigned int len);

TINY_CRYPTO_API
TINY_LOR
void sha512_final(sha512_ctx *ctx, unsigned char *digest);

TINY_CRYPTO_API
TINY_LOR
void sha512_hash(uint8_t out[SHA512_DIGEST_SIZE], const uint8_t *message, uint64_t length);


TINY_END_DECLS

#endif /* __SHA512_H__ */