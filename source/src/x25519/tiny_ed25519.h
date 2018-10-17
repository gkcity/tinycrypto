/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   tiny_ed25519.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __TINY_ED25519_H__
#define __TINY_ED25519_H__

#include <tiny_base.h>
#include <stddef.h>
#include <tiny_lor.h>
#include <common/tiny_crypto_api.h>

TINY_BEGIN_DECLS


#define ED25519_PRIVATE_KEY_LENGTH      32
#define ED25519_PUBLIC_KEY_LENGTH       32
#define ED25519_SIGNATURE_LENGTH        64

typedef struct _ED25519PrivateKey
{
    uint8_t value[ED25519_PRIVATE_KEY_LENGTH];
    uint32_t length;
} ED25519PrivateKey;

typedef struct _ED25519PublicKey
{
    uint8_t value[ED25519_PUBLIC_KEY_LENGTH];
    uint32_t length;
} ED25519PublicKey;

typedef struct _ED25519Signature
{
    uint8_t value[ED25519_SIGNATURE_LENGTH];
    uint32_t length;
} ED25519Signature;

typedef struct _Ed25519KeyPair
{
    ED25519PrivateKey privateKey;
    ED25519PublicKey publicKey;
} Ed25519KeyPair;

TINY_LOR
TINY_CRYPTO_API
void tiny_ed25519_generateKeyPair(Ed25519KeyPair *thiz);

TINY_LOR
TINY_CRYPTO_API
void tiny_ed25519_copyKeyPair(Ed25519KeyPair *dst, Ed25519KeyPair *src);

TINY_LOR
TINY_CRYPTO_API
TinyRet tiny_ed25519_verify(ED25519PublicKey *key,
                            ED25519Signature *signature,
                            const uint8_t *data,
                            uint32_t length);

TINY_LOR
TINY_CRYPTO_API
void tiny_ed25519_sign(ED25519PrivateKey *privateKey,
                       ED25519PublicKey *publicKey,
                       ED25519Signature *signature,
                       const uint8_t *data,
                       uint32_t length);

TINY_END_DECLS

#endif /* __TINY_ED25519_H__ */