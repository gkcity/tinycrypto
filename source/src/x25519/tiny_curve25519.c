/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   tiny_curve25519.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include <tiny_random.h>
#include "tiny_curve25519.h"
#include "x25519/fe.h"
#include "x25519/ge.h"
#if 1
#include "crypt25519.h"
#else
#include "ed25519_key_exchange.h"
#endif

TINY_LOR
void Curve25519_GenerateKeyPair(Curve25519PublicKey *publicKey, Curve25519PrivateKey *privateKey)
{
#if 1
    tiny_random_create(privateKey->value, CURVE25519_PRIVATE_KEY_LENGTH);
    crypto_scalarmult_curve25519_base(publicKey->value, privateKey->value);

    privateKey->value[0] &= 248;
    privateKey->value[31] = (uint8_t)((privateKey->value[31] & 127) | 64);

    privateKey->length = CURVE25519_PRIVATE_KEY_LENGTH;
    publicKey->length = CURVE25519_PUBLIC_KEY_LENGTH;
#else
    ge_p3 A;
    fe x1, tmp0, tmp1;

    tiny_random_create(privateKey->value, CURVE25519_PRIVATE_KEY_LENGTH);

    ge_scalarmult_base(&A, privateKey->value);
    ge_p3_tobytes(publicKey->value, &A);

    /* convert edwards to montgomery */
    /* due to CodesInChaos: montgomeryX = (edwardsY + 1)*inverse(1 - edwardsY) mod p */
    fe_frombytes(x1, publicKey->value);
    fe_1(tmp1);
    fe_add(tmp0, x1, tmp1);
    fe_sub(tmp1, tmp1, x1);
    fe_invert(tmp1, tmp1);
    fe_mul(x1, tmp0, tmp1);

    fe_tobytes(publicKey->value, x1);
#endif
}

TINY_LOR
void Curve25519_GenerateSharedKey(Curve25519PrivateKey *b, Curve25519PublicKey *A, Curve25519SharedKey *sharedKey)
{
#if 1
    crypto_scalarmult_curve25519(sharedKey->value, b->value, A->value);
    sharedKey->length = CURVE25519_SHARED_KEY_LENGTH;
#else
    fe mont_x, mont_x_minus_one, mont_x_plus_one, inv_mont_x_plus_one;
    fe one;
    fe ed_y;
    unsigned char ed_public_key[32];

    /*
     * Step 1. Convert the Curve25519 public key into an Ed25519 public key
     */
    fe_frombytes(mont_x, A->value);
    fe_1(one);
    fe_sub(mont_x_minus_one, mont_x, one);
    fe_add(mont_x_plus_one, mont_x, one);
    fe_invert(inv_mont_x_plus_one, mont_x_plus_one);
    fe_mul(ed_y, mont_x_minus_one, inv_mont_x_plus_one);
    fe_tobytes(ed_public_key, ed_y);

    /*
     * Step 2. Compute shared secred
     */
    ed25519_key_exchange(sharedKey->value, ed_public_key, b->value);
#endif
}