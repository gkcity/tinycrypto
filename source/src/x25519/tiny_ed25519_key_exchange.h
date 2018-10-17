/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   tiny_ed25519_key_exchange.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __TINY_ED25519_KEY_EXCHANGE_H__
#define __TINY_ED25519_KEY_EXCHANGE_H__

#include <tiny_base.h>
#include <tiny_lor.h>

TINY_BEGIN_DECLS


void tiny_ed25519_key_exchange(unsigned char *sharedSecret,
                               const unsigned char *publicKey,
                               const unsigned char *privateKey);


TINY_END_DECLS

#endif /* __TINY_ED25519_KEY_EXCHANGE_H__ */