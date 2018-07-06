/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   HKDF.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __HKDF_H__
#define __HKDF_H__

#include <tiny_base.h>
#include <tiny_lor.h>
#include <common/tiny_crypto_api.h>

TINY_BEGIN_DECLS


#define HKDF_HASH_MAX_LEN       128
#define HKDF_KEY_LEN            32

typedef struct _HKDF
{
    uint8_t         value[HKDF_HASH_MAX_LEN];
    uint32_t        length;
} HKDF;

typedef enum _DigestType
{
    HASH_DIGEST_SHA1 = 0,
    HASH_DIGEST_SHA512 = 1,
} DigestType;

TINY_CRYPTO_API
TINY_LOR
void HKDF_Generate(HKDF *thiz,
                   DigestType digestType,
                   const uint8_t *salt,
                   uint32_t salt_length,
                   const uint8_t *info,
                   uint32_t info_length,
                   const uint8_t *ikm,
                   uint32_t ikm_length);


TINY_END_DECLS

#endif /* __HKDF_H__ */