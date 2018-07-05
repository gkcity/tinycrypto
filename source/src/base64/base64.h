/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   base64.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __BASE64_H__
#define __BASE64_H__

#include <tiny_base.h>
#include <tiny_lor.h>
#include <common/tiny_crypto_api.h>

TINY_BEGIN_DECLS


TINY_LOR
TINY_CRYPTO_API
uint32_t base64_decode_out_length(const char *string);

TINY_LOR
TINY_CRYPTO_API

uint32_t base64_decode(const char *string, uint8_t *out);

TINY_LOR
TINY_CRYPTO_API
uint32_t base64_encode_out_length(int bytesLength);

TINY_LOR
TINY_CRYPTO_API
uint32_t base64_encode(const uint8_t *bytes, int length, char *out);


TINY_END_DECLS

#endif /* __BASE64_H__ */
