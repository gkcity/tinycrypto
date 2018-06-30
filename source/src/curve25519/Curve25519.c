/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   Curve25519.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include <tiny_random.h>
#include "Curve25519.h"
#include "crypt25519/crypt25519.h"

TINY_LOR
void Curve25519_GenerateKeyPair(Curve25519PublicKey *publicKey, Curve25519PrivateKey *privateKey)
{
    tiny_random_create(privateKey->value, CURVE25519_PRIVATE_KEY_LENGTH);
    crypto_scalarmult_curve25519_base(publicKey->value, privateKey->value);

    privateKey->value[0] &= 248;
    privateKey->value[31] = (uint8_t)((privateKey->value[31] & 127) | 64);

    privateKey->length = CURVE25519_PRIVATE_KEY_LENGTH;
    publicKey->length = CURVE25519_PUBLIC_KEY_LENGTH;
}

TINY_LOR
void Curve25519_GenerateSharedKey(Curve25519PrivateKey *b, Curve25519PublicKey *A, Curve25519SharedKey *sharedKey)
{
    crypto_scalarmult_curve25519(sharedKey->value, b->value, A->value);
    sharedKey->length = CURVE25519_SHARED_KEY_LENGTH;
}