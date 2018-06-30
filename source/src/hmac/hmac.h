/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   hmac.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __HMAC_H__
#define __HMAC_H__

#include <tiny_base.h>
#include <hap_api.h>
#include <sha/sha512.h>
#include <tiny_lor.h>

TINY_BEGIN_DECLS


HAP_API
TINY_LOR
void hmac_sha512(uint8_t out[SHA512_DIGEST_SIZE],
                 const uint8_t *salt,
                 uint32_t salt_length,
                 const uint8_t *data,
                 uint32_t data_length);


TINY_END_DECLS

#endif /* __HMAC_H__ */