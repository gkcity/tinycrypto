/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   chacha20poly1305.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __CHACHA20_POLY1305_H__
#define __CHACHA20_POLY1305_H__

#include <tiny_lor.h>
#include <tiny_base.h>
#include <common/tiny_crypto_api.h>

TINY_BEGIN_DECLS


TINY_CRYPTO_API
TINY_LOR
TinyRet chacha20poly1305_decrypt(const uint8_t key[64],
                                 uint32_t keyLength,
                                 const uint8_t nonce[8],
                                 const uint8_t *ciphertext,
                                 uint32_t ciphertextLength,
                                 const uint8_t mac[16],
                                 uint8_t *plaintext,
                                 const uint8_t *additional,
                                 uint32_t additionalLength);

TINY_CRYPTO_API
TINY_LOR
void chacha20poly1305_encrypt(const uint8_t *key,
                              uint32_t keyLength,
                              const uint8_t nonce[8],
                              const uint8_t *plaintext,
                              uint32_t plaintextLength,
                              uint8_t *ciphertext,
                              uint8_t mac[16],
                              const uint8_t *additional,
                              uint32_t additionalLength);


TINY_END_DECLS

#endif /* __CHACHA20_POLY1305_H__ */