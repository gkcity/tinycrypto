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

#include <sha/sha512.h>
#include "tiny_ed25519.h"
#include "crypt25519/crypt25519.h"

TINY_LOR
void tiny_ed25519_generateKeyPair(Ed25519KeyPair *thiz)
{
    crypto_ed25519_keypair(thiz->publicKey.value, thiz->privateKey.value);
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
    uint8_t result[1024];
    unsigned long long int resultLength = 0;
    uint8_t message[ED25519_SIGNATURE_LENGTH + 32 + 36 + 32];
    uint64_t messageLength = 0;

    memcpy(message, signature->value, signature->length);
    memcpy(message + signature->length, data, length);
    messageLength = signature->length + length;

    return crypto_ed25519_verify(result, &resultLength, message, messageLength, key->value) ? TINY_RET_OK : TINY_RET_E_ARG_INVALID;
}

TINY_LOR
void tiny_ed25519_sign(ED25519PrivateKey *key,
                       ED25519Signature *signature,
                       const uint8_t *data,
                       uint32_t length)
{
    uint8_t buf[1024];
    unsigned long long int len = 0;

    memset(buf, 0, 1024);
    memcpy(buf + 64, data, length);

    crypto_ed25519_sign(buf, &len, buf + 64, length, key->value);

    memcpy(signature->value, buf, 64);
    signature->length = 64;
}