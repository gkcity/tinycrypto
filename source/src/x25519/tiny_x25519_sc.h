/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   tiny_x25519_sc.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __TINY_X25519_SC_H__
#define __TINY_X25519_SC_H__

#include <tiny_base.h>

TINY_BEGIN_DECLS

/*
The set of scalars is \Z/l
where l = 2^252 + 27742317777372353535851937790883648493.
*/

void x25519_sc_reduce(unsigned char *s);
void x25519_sc_muladd(unsigned char *s, const unsigned char *a, const unsigned char *b, const unsigned char *c);


TINY_END_DECLS

#endif /* __TINY_X25519_SC_H__ */