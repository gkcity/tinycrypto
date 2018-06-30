/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   SrpVectors.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __SRP_VECTORS_H__
#define __SRP_VECTORS_H__

#include <tiny_base.h>

TINY_BEGIN_DECLS


typedef struct _SrpVectors
{
    const char      *I;
    const char      *P;
    const char      *s;
    const char      *v;
    const char      *a;
    const char      *A;
    const char      *b;
    const char      *B;
    const char      *u;
    const char      *S;
    const char      *K;
} SrpVectors;


TINY_END_DECLS

#endif /* __SRP_VECTORS_H__ */