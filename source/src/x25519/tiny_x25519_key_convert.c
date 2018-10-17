/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   x25519_key_convert.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include "tiny_x25519_key_convert.h"
#include "tiny_x25519_fe.h"

void tiny_convert_curve25519_pk_to_ed25519_pk(uint8_t *in, uint8_t *out)
{
    fe mont_x, mont_x_minus_one, mont_x_plus_one, inv_mont_x_plus_one;
    fe one;
    fe ed_y;

    fe_frombytes(mont_x, in);
    fe_1(one);
    fe_sub(mont_x_minus_one, mont_x, one);
    fe_add(mont_x_plus_one, mont_x, one);
    fe_invert(inv_mont_x_plus_one, mont_x_plus_one);
    fe_mul(ed_y, mont_x_minus_one, inv_mont_x_plus_one);
    fe_tobytes(out, ed_y);
}