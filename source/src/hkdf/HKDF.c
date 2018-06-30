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
                   const uint8_t *salt,
                   uint32_t salt_length,
                   const uint8_t *info,
                   uint32_t info_length,
                   const uint8_t *ikm,
                   uint32_t ikm_length)
{
    thiz->length = HKDF_KEY_LEN;
    hmac_sha512(thiz->value, salt, salt_length, ikm, ikm_length);
    hmac_sha512(thiz->value, thiz->value, 64, info, info_length);
}