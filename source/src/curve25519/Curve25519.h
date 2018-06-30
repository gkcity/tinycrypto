/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   Curve25519.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __CURVE25519_H__
#define __CURVE25519_H__

#include <tiny_base.h>
#include <stddef.h>
#include <tiny_lor.h>
#include <common/tiny_crypto_api.h>

TINY_BEGIN_DECLS


#define CURVE25519_PRIVATE_KEY_LENGTH      32
#define CURVE25519_PUBLIC_KEY_LENGTH       32
#define CURVE25519_SHARED_KEY_LENGTH       32

typedef struct _Curve25519PrivateKey
{
    uint8_t value[CURVE25519_PRIVATE_KEY_LENGTH];
    uint32_t length;
} Curve25519PrivateKey;

typedef struct _Curve25519PublicKey
{
    uint8_t value[CURVE25519_PUBLIC_KEY_LENGTH];
    uint32_t length;
} Curve25519PublicKey;

typedef struct _Curve25519SharedKey
{
    uint8_t value[CURVE25519_SHARED_KEY_LENGTH];
    uint32_t length;
} Curve25519SharedKey;

TINY_CRYPTO_API
TINY_LOR
void Curve25519_GenerateKeyPair(Curve25519PublicKey *publicKey, Curve25519PrivateKey *privateKey);

TINY_CRYPTO_API
TINY_LOR
void Curve25519_GenerateSharedKey(Curve25519PrivateKey *b, Curve25519PublicKey *A, Curve25519SharedKey *sharedKey);


TINY_END_DECLS

#endif /* __CURVE25519_H__ */