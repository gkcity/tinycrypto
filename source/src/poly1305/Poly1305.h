/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   poly1305.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __POLY_1305_H__
#define __POLY_1305_H__

#include <tiny_base.h>
#include <tiny_lor.h>

TINY_BEGIN_DECLS


typedef struct _Poly1305
{
    size_t aligner;
    unsigned char opaque[136];
} Poly1305;

TINY_LOR
void Poly1305_Initialize(Poly1305 *ctx, const unsigned char *key);

TINY_LOR
void Poly1305_Update(Poly1305 *ctx, const unsigned char *in, size_t len);

TINY_LOR
void Poly1305_Finish(Poly1305 *ctx, unsigned char *mac);


TINY_END_DECLS

#endif /* __POLY_1305_H__ */