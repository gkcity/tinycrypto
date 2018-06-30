/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   crypt25519.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __CRYPT_25519_H__
#define __CRYPT_25519_H__

#include <tiny_base.h>
#include <tiny_lor.h>

TINY_BEGIN_DECLS


TINY_LOR
int crypto_ed25519_sign(unsigned char *signature,
                        unsigned long long *signature_length,
                        const unsigned char *data,
                        unsigned long long length,
                        const unsigned char *secret);

TINY_LOR
bool crypto_ed25519_verify(unsigned char *,
                           unsigned long long *,
                           const unsigned char *,
                           unsigned long long,
                           const unsigned char *);

TINY_LOR
void crypto_ed25519_keypair(unsigned char *publicKey, unsigned char *privateKey);

TINY_LOR
int crypto_scalarmult_curve25519(unsigned char *, const unsigned char *, const unsigned char *);

TINY_LOR
int crypto_scalarmult_curve25519_base(unsigned char *, const unsigned char *);


TINY_END_DECLS

#endif /* __CRYPT_25519_H__ */