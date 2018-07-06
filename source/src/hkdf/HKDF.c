/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   HKDF.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include <hmac/hmac.h>
#include "HKDF.h"

TINY_LOR
void HKDF_Generate(HKDF *thiz,
                   DigestType digestType,
                   const uint8_t *salt,
                   uint32_t salt_length,
                   const uint8_t *info,
                   uint32_t info_length,
                   const uint8_t *ikm,
                   uint32_t ikm_length)
{
    size_t size = 0;

    switch (digestType)
    {
        case HASH_DIGEST_SHA1:
            // BUG !!! thiz->value is always 0x00
            hmac_sha1(thiz->value, &size, salt, salt_length, ikm, ikm_length);
            hmac_sha1(thiz->value, &size, thiz->value, SHA1_DIGEST_SIZE, info, info_length);
            thiz->length = HKDF_KEY_LEN;
            break;

        case HASH_DIGEST_SHA512:
            hmac_sha512(thiz->value, salt, salt_length, ikm, ikm_length);
            hmac_sha512(thiz->value, thiz->value, SHA512_DIGEST_SIZE, info, info_length);
            thiz->length = HKDF_KEY_LEN;
            break;
    }
}