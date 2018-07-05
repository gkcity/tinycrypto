/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   SecretKey.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __SECRET_KEY_H__
#define __SECRET_KEY_H__

#include <tiny_base.h>

TINY_BEGIN_DECLS


#define SECRET_KEY_LENGTH       64

typedef struct _SecretKey
{
    uint8_t         value[SECRET_KEY_LENGTH];
    uint32_t        length;
} SecretKey;


TINY_END_DECLS

#endif /* __SECRET_KEY_H__ */