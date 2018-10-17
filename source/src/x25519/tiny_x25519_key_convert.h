/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   tiny_x25519_key_convert.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __TINY_X25519_KEY_CONVERT_H__
#define __TINY_X25519_KEY_CONVERT_H__

#include <tiny_base.h>

TINY_BEGIN_DECLS


void tiny_convert_curve25519_pk_to_ed25519_pk(uint8_t *in, uint8_t *out);


TINY_END_DECLS

#endif /* __TINY_X25519_KEY_CONVERT_H__ */