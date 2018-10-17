/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   tiny_ed25519_key_exchange.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include "tiny_ed25519_key_exchange.h"
#include "tiny_x25519_fe.h"


static void zeroize(void *v, size_t n)
{
    volatile unsigned char *p = v; while(n--) *p++ = 0;
}

void tiny_ed25519_key_exchange(unsigned char *shared_secret,
                               const unsigned char *public_key,
                               const unsigned char *private_key)
{
    unsigned char e[32];
    unsigned int i;

    x25519_fe x1;
    x25519_fe x2;
    x25519_fe z2;
    x25519_fe x3;
    x25519_fe z3;
    x25519_fe tmp0;
    x25519_fe tmp1;

    int pos;
    unsigned int swap;
    unsigned int b;

    /* copy the private key and make sure it's valid */
    for (i = 0; i < 32; ++i)
    {
        e[i] = private_key[i];
    }

    e[0] &= 248;
    e[31] &= 63;
    e[31] |= 64;

    /* unpack the public key and convert edwards to montgomery */
    /* due to CodesInChaos: montgomeryX = (edwardsY + 1)*inverse(1 - edwardsY) mod p */
    x25519_fe_frombytes(x1, public_key);
    x25519_fe_1(tmp1);
    x25519_fe_add(tmp0, x1, tmp1);
    x25519_fe_sub(tmp1, tmp1, x1);
    x25519_fe_invert(tmp1, tmp1);
    x25519_fe_mul(x1, tmp0, tmp1);

    x25519_fe_1(x2);
    x25519_fe_0(z2);
    x25519_fe_copy(x3, x1);
    x25519_fe_1(z3);

    swap = 0;
    for (pos = 254; pos >= 0; --pos)
    {
        b = e[pos / 8] >> (pos & 7);
        b &= 1;
        swap ^= b;
        x25519_fe_cswap(x2, x3, swap);
        x25519_fe_cswap(z2, z3, swap);
        swap = b;

        /* from montgomery.h */
        x25519_fe_sub(tmp0, x3, z3);
        x25519_fe_sub(tmp1, x2, z2);
        x25519_fe_add(x2, x2, z2);
        x25519_fe_add(z2, x3, z3);
        x25519_fe_mul(z3, tmp0, x2);
        x25519_fe_mul(z2, z2, tmp1);
        x25519_fe_sq(tmp0, tmp1);
        x25519_fe_sq(tmp1, x2);
        x25519_fe_add(x3, z3, z2);
        x25519_fe_sub(z2, z3, z2);
        x25519_fe_mul(x2, tmp1, tmp0);
        x25519_fe_sub(tmp1, tmp1, tmp0);
        x25519_fe_sq(z2, z2);
        x25519_fe_mul121666(z3, tmp1);
        x25519_fe_sq(x3, x3);
        x25519_fe_add(tmp0, tmp0, z3);
        x25519_fe_mul(z3, x1, z2);
        x25519_fe_mul(z2, tmp1, tmp0);
    }

    x25519_fe_cswap(x2, x3, swap);
    x25519_fe_cswap(z2, z3, swap);

    x25519_fe_invert(z2, z2);
    x25519_fe_mul(x2, x2, z2);
    x25519_fe_tobytes(shared_secret, x2);

    zeroize(e, 32);
}