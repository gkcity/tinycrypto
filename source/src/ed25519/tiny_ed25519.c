/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   tiny_ed25519.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include "tiny_ed25519.h"
#include "ed25519.h"

TINY_LOR
void tiny_ed25519_generateKeyPair(Ed25519KeyPair *thiz)
{
    ed25519_make_key_pair(thiz->publicKey.value, thiz->privateKey.value);
    thiz->publicKey.length = ED25519_PUBLIC_KEY_LENGTH;
    thiz->privateKey.length = ED25519_PRIVATE_KEY_LENGTH;
}

TINY_LOR
void tiny_ed25519_copyKeyPair(Ed25519KeyPair *dst, Ed25519KeyPair *src)
{
    if (dst != src)
    {
        memcpy(dst->privateKey.value, src->privateKey.value, src->privateKey.length);
        memcpy(dst->publicKey.value, src->publicKey.value, src->publicKey.length);
        dst->privateKey.length = src->privateKey.length;
        dst->publicKey.length = src->publicKey.length;
        return;
    }
}

TINY_LOR
TinyRet tiny_ed25519_verify(ED25519PublicKey *key,
                            ED25519Signature *signature,
                            const uint8_t *data,
                            uint32_t length)
{
    return ed25519_verify(data, length, signature->value, key->value) == 0 ? TINY_RET_OK : TINY_RET_E_ARG_INVALID;
}

// sometimes has bug !!!
TINY_LOR
void tiny_ed25519_sign(ED25519PrivateKey *privateKey,
                       ED25519PublicKey *publicKey,
                       ED25519Signature *signature,
                       const uint8_t *data,
                       uint32_t length)
{
    ed25519_sign(signature->value, data, length, publicKey->value, privateKey->value);
    signature->length = 64;
}