/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   tiny_bignum.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __TINY_BIGNUM_H__
#define __TINY_BIGNUM_H__

#include <tiny_base.h>

TINY_BEGIN_DECLS


//#ifdef ESP
#if 0
    #include "tiny_bignum_esp.h"
#else
    #include "tiny_bignum_polarssl.h"
#endif


TINY_END_DECLS

#endif /* __TINY_BIGNUM_H__ */
