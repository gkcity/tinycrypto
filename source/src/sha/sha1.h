/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   sha1.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __SHA1_H__
#define __SHA1_H__

#include <tiny_base.h>
#include <tiny_lor.h>
#include "common/tiny_crypto_api.h"

TINY_BEGIN_DECLS


#define SHA1_DIGEST_SIZE        20
#define SHA1_BLOCKSIZE          64

typedef struct
{
    uint32_t    state[5];       /**< Context state */
    uint32_t    count[2];       /**< Counter       */
    uint8_t     buffer[64];     /**< SHA-1 buffer  */
} sha1_ctx;

TINY_LOR
void sha1_init(sha1_ctx *ctx);

TINY_LOR
void sha1_update(sha1_ctx *ctx, const void *p, size_t len);

TINY_LOR
void sha1_final(uint8_t digest[SHA1_DIGEST_SIZE], sha1_ctx *context);


TINY_END_DECLS

#endif /* __SHA1_H__ */