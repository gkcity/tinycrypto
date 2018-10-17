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
#include "tiny_x25519_fe.h"
#include "tiny_x25519_ge.h"
#include "tiny_ed25519_key_exchange.h"
#include "tiny_x25519_key_convert.h"

static int curve25519_getpub(unsigned char* public_key, const unsigned char* private_key)
{
    x25519_ge_p3 A;
    x25519_fe x1, tmp0, tmp1;
    x25519_ge_scalarmult_base(&A, private_key);
    x25519_ge_p3_tobytes(public_key, &A);

    /* convert edwards to montgomery */
    /* due to CodesInChaos: montgomeryX = (edwardsY + 1)*inverse(1 - edwardsY) mod p */
    x25519_fe_frombytes(x1, public_key);
    x25519_fe_1(tmp1);
    x25519_fe_add(tmp0, x1, tmp1);
    x25519_fe_sub(tmp1, tmp1, x1);
    x25519_fe_invert(tmp1, tmp1);
    x25519_fe_mul(x1, tmp0, tmp1);

    x25519_fe_tobytes(public_key, x1);
    return 0;
}

TINY_LOR
void tiny_curve25519_generateKeyPair(Curve25519PublicKey *publicKey, Curve25519PrivateKey *privateKey)
{
    tiny_random_create(privateKey->value, CURVE25519_PRIVATE_KEY_LENGTH);
    privateKey->value[0] &= 248;
    privateKey->value[31] = (uint8_t)((privateKey->value[31] & 127) | 64);
    privateKey->length = CURVE25519_PRIVATE_KEY_LENGTH;

    curve25519_getpub(publicKey->value, privateKey->value);
    publicKey->length = CURVE25519_PUBLIC_KEY_LENGTH;
}

TINY_LOR
void tiny_curve25519_generateSharedKey(Curve25519PrivateKey *b, Curve25519PublicKey *A, Curve25519SharedKey *sharedKey)
{
    /*
     * Step 1. Convert the Curve25519 public key into an Ed25519 public key
     */
    unsigned char ed_public_key[32];
    tiny_convert_curve25519_pk_to_ed25519_pk(A->value, ed_public_key);

    /*
     * Step 2. Compute shared secret
     */
    tiny_ed25519_key_exchange(sharedKey->value, ed_public_key, b->value);

    sharedKey->length = CURVE25519_SHARED_KEY_LENGTH;
}