/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   base64.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __BASE64_H__
#define __BASE64_H__

#include <tiny_base.h>

TINY_BEGIN_DECLS


uint32_t base64_decode(const char *string, uint8_t *out);

uint32_t base64_encode(const uint8_t *bytes, int length, char *out);


TINY_END_DECLS

#endif /* __BASE64_H__ */
