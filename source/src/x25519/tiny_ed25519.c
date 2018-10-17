/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   tiny_ed25519.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include "tiny_ed25519.h"
#include "tiny_curve25519.h"
#include <sha/sha512.h>
#include "tiny_x25519_ge.h"
#include "tiny_x25519_sc.h"
#include "tiny_x25519_key_convert.h"

TINY_LOR
void tiny_ed25519_generateKeyPair(Ed25519KeyPair *thiz)
{
    Curve25519PublicKey publicKey;
    Curve25519PrivateKey privateKey;

    tiny_curve25519_generateKeyPair(&publicKey, &privateKey);
    tiny_convert_curve25519_pk_to_ed25519_pk(publicKey.value, thiz->publicKey.value);

    memcpy(thiz->privateKey.value, privateKey.value, ED25519_PRIVATE_KEY_LENGTH);
    thiz->publicKey.length = ED25519_PUBLIC_KEY_LENGTH;
    thiz->privateKey.length = ED25519_PRIVATE_KEY_LENGTH;
}

TINY_LOR
void tiny_ed25519_copyKeyPair(Ed25519KeyPair *dst, Ed25519KeyPair *src)
{
    if (dst != src)
    {
        memcpy(dst->privateKey.value, src->privateKey.value, src->privateKey.length);
        memcpy(dst->publicKey.value, src->publicKey.value, src->publicKey.length);
        dst->privateKey.length = src->privateKey.length;
        dst->publicKey.length = src->publicKey.length;
        return;
    }
}

static int consttime_equal(const unsigned char *x, const unsigned char *y)
{
    unsigned char r = 0;

    r = x[0] ^ y[0];
#define F(i) r |= x[i] ^ y[i]
    F(1);
    F(2);
    F(3);
    F(4);
    F(5);
    F(6);
    F(7);
    F(8);
    F(9);
    F(10);
    F(11);
    F(12);
    F(13);
    F(14);
    F(15);
    F(16);
    F(17);
    F(18);
    F(19);
    F(20);
    F(21);
    F(22);
    F(23);
    F(24);
    F(25);
    F(26);
    F(27);
    F(28);
    F(29);
    F(30);
    F(31);
#undef F

    return !r;
}

TINY_LOR
TinyRet tiny_ed25519_verify(ED25519PublicKey *key,
                            ED25519Signature *signature,
                            const uint8_t *data,
                            uint32_t length)
{
    TinyRet ret = TINY_RET_OK;

    do
    {
        unsigned char h[64];
        unsigned char checker[32];
        sha512_ctx hash;
        ge_p3 A;
        ge_p2 R;

        if (signature->value[63] & 224)
        {
            ret = TINY_RET_E_ARG_INVALID;
            break;
        }

        if (ge_frombytes_negate_vartime(&A, key->value) != 0)
        {
            ret = TINY_RET_E_ARG_INVALID;
            break;
        }

        sha512_init(&hash);
        sha512_update(&hash, signature->value, 32);
        sha512_update(&hash, key->value, 32);
        sha512_update(&hash, data, length);
        sha512_final(&hash, h);

        sc_reduce(h);
        ge_double_scalarmult_vartime(&R, h, &A, signature->value + 32);
        ge_tobytes(checker, &R);

        if (!consttime_equal(checker, signature->value))
        {
            ret = TINY_RET_E_ARG_INVALID;
            break;
        }
    } while (false);

    return ret;
}

TINY_LOR
void tiny_ed25519_sign(ED25519PrivateKey *privateKey,
                       ED25519PublicKey *publicKey,
                       ED25519Signature *signature,
                       const uint8_t *data,
                       uint32_t length)
{
    sha512_ctx hash;
    unsigned char hram[64];
    unsigned char r[64];
    ge_p3 R;

    sha512_init(&hash);
    sha512_update(&hash, privateKey->value + 32, 32);
    sha512_update(&hash, data, length);
    sha512_final(&hash, r);

    sc_reduce(r);
    ge_scalarmult_base(&R, r);
    ge_p3_tobytes(signature->value, &R);

    sha512_init(&hash);
    sha512_update(&hash, signature->value, 32);
    sha512_update(&hash, publicKey->value, 32);
    sha512_update(&hash, data, length);
    sha512_final(&hash, hram);

    sc_reduce(hram);
    sc_muladd(signature->value + 32, hram, privateKey->value, r);

    signature->length = 64;
}