/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   tiny_x25519_fe.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __TINY_X25519_FE_H__
#define __TINY_X25519_FE_H__

#include <tiny_base.h>

TINY_BEGIN_DECLS


/*
    x25519_fe means field element.
    Here the field is \Z/(2^255-19).
    An element t, entries t[0]...t[9], represents the integer
    t[0]+2^26 t[1]+2^51 t[2]+2^77 t[3]+2^102 t[4]+...+2^230 t[9].
    Bounds on each t[i] vary depending on context.
*/


typedef int32_t x25519_fe[10];


void x25519_fe_0(x25519_fe h);
void x25519_fe_1(x25519_fe h);

void x25519_fe_frombytes(x25519_fe h, const unsigned char *s);
void x25519_fe_tobytes(unsigned char *s, const x25519_fe h);

void x25519_fe_copy(x25519_fe h, const x25519_fe f);
int x25519_fe_isnegative(const x25519_fe f);
int x25519_fe_isnonzero(const x25519_fe f);
void x25519_fe_cmov(x25519_fe f, const x25519_fe g, unsigned int b);
void x25519_fe_cswap(x25519_fe f, x25519_fe g, unsigned int b);

void x25519_fe_neg(x25519_fe h, const x25519_fe f);
void x25519_fe_add(x25519_fe h, const x25519_fe f, const x25519_fe g);
void x25519_fe_invert(x25519_fe out, const x25519_fe z);
void x25519_fe_sq(x25519_fe h, const x25519_fe f);
void x25519_fe_sq2(x25519_fe h, const x25519_fe f);
void x25519_fe_mul(x25519_fe h, const x25519_fe f, const x25519_fe g);
void x25519_fe_mul121666(x25519_fe h, x25519_fe f);
void x25519_fe_pow22523(x25519_fe out, const x25519_fe z);
void x25519_fe_sub(x25519_fe h, const x25519_fe f, const x25519_fe g);


TINY_END_DECLS

#endif /* __TINY_X25519_FE_H__ */
