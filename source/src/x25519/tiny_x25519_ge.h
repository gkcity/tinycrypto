/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   tiny_x25519_ge.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __TINY_X25519_GE_H__
#define __TINY_X25519_GE_H__

#include <tiny_base.h>
#include "tiny_x25519_fe.h"

TINY_BEGIN_DECLS


/*
ge means group element.

Here the group is the set of pairs (x,y) of field elements (see x25519_fe.h)
satisfying -x^2 + y^2 = 1 + d x^2y^2
where d = -121665/121666.

Representations:
  x25519_ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
  x25519_ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
  x25519_ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
  x25519_ge_precomp (Duif): (y+x,y-x,2dxy)
*/

typedef struct {
  x25519_fe X;
  x25519_fe Y;
  x25519_fe Z;
} x25519_ge_p2;

typedef struct {
  x25519_fe X;
  x25519_fe Y;
  x25519_fe Z;
  x25519_fe T;
} x25519_ge_p3;

typedef struct {
  x25519_fe X;
  x25519_fe Y;
  x25519_fe Z;
  x25519_fe T;
} x25519_ge_p1p1;

typedef struct {
  x25519_fe yplusx;
  x25519_fe yminusx;
  x25519_fe xy2d;
} x25519_ge_precomp;

typedef struct {
  x25519_fe YplusX;
  x25519_fe YminusX;
  x25519_fe Z;
  x25519_fe T2d;
} x25519_ge_cached;

void x25519_ge_p3_tobytes(unsigned char *s, const x25519_ge_p3 *h);
void x25519_ge_tobytes(unsigned char *s, const x25519_ge_p2 *h);
int x25519_ge_frombytes_negate_vartime(x25519_ge_p3 *h, const unsigned char *s);

void x25519_ge_add(x25519_ge_p1p1 *r, const x25519_ge_p3 *p, const x25519_ge_cached *q);
void x25519_ge_sub(x25519_ge_p1p1 *r, const x25519_ge_p3 *p, const x25519_ge_cached *q);
void x25519_ge_double_scalarmult_vartime(x25519_ge_p2 *r, const unsigned char *a, const x25519_ge_p3 *A, const unsigned char *b);
void x25519_ge_madd(x25519_ge_p1p1 *r, const x25519_ge_p3 *p, const x25519_ge_precomp *q);
void x25519_ge_msub(x25519_ge_p1p1 *r, const x25519_ge_p3 *p, const x25519_ge_precomp *q);
void x25519_ge_scalarmult_base(x25519_ge_p3 *h, const unsigned char *a);

void x25519_ge_p1p1_to_p2(x25519_ge_p2 *r, const x25519_ge_p1p1 *p);
void x25519_ge_p1p1_to_p3(x25519_ge_p3 *r, const x25519_ge_p1p1 *p);
void x25519_ge_p2_0(x25519_ge_p2 *h);
void x25519_ge_p2_dbl(x25519_ge_p1p1 *r, const x25519_ge_p2 *p);
void x25519_ge_p3_0(x25519_ge_p3 *h);
void x25519_ge_p3_dbl(x25519_ge_p1p1 *r, const x25519_ge_p3 *p);
void x25519_ge_p3_to_cached(x25519_ge_cached *r, const x25519_ge_p3 *p);
void x25519_ge_p3_to_p2(x25519_ge_p2 *r, const x25519_ge_p3 *p);


TINY_END_DECLS

#endif /* __TINY_X25519_GE_H__ */
