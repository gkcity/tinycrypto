/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   hmac.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include "hmac.h"

void hmac_sha1(uint8_t out[SHA1_DIGEST_SIZE],
               size_t *out_length,
               const uint8_t *salt,
               size_t salt_length,
               const uint8_t *data,
               size_t data_length)

{
    sha1_ctx ictx, octx;
    uint8_t isha[SHA1_DIGEST_SIZE];
    uint8_t osha[SHA1_DIGEST_SIZE];
    uint8_t key[SHA1_DIGEST_SIZE];
    uint8_t buf[SHA1_BLOCKSIZE];
    size_t i;

    if (salt_length > SHA1_BLOCKSIZE)
    {
        sha1_ctx tctx;

        sha1_init(&tctx);
        sha1_update(&tctx, salt, salt_length);
        sha1_final(key, &tctx);

        salt = key;
        salt_length = SHA1_DIGEST_SIZE;
    }

    /**** Inner Digest ****/

    sha1_init(&ictx);

    /* Pad the key for inner digest */
    for (i = 0; i < salt_length; ++i)
    {
        buf[i] = salt[i] ^ 0x36;
    }
    for (i = salt_length; i < SHA1_BLOCKSIZE; ++i)
    {
        buf[i] = 0x36;
    }

    sha1_update(&ictx, buf, SHA1_BLOCKSIZE);
    sha1_update(&ictx, data, data_length);

    sha1_final(isha, &ictx);

    /**** Outer Digest ****/

    sha1_init(&octx);

    /* Pad the key for outter digest */

    for (i = 0; i < salt_length; ++i)
    {
        buf[i] = salt[i] ^ 0x5c;
    }
    for (i = salt_length; i < SHA1_BLOCKSIZE; ++i)
    {
        buf[i] = 0x5c;
    }

    sha1_update(&octx, buf, SHA1_BLOCKSIZE);
    sha1_update(&octx, isha, SHA1_DIGEST_SIZE);

    sha1_final(osha, &octx);

    /* truncate and print the results */
    *out_length = *out_length > SHA1_DIGEST_SIZE ? SHA1_DIGEST_SIZE : *out_length;
    memcpy(out, osha, *out_length);
}

TINY_LOR
void hmac_sha512(uint8_t out[SHA512_DIGEST_SIZE],
                 const uint8_t *salt,
                 uint32_t salt_length,
                 const uint8_t *data,
                 uint32_t data_length)
{
#if 0
    // only works on gcc
    uint8_t message1[128 + data_length];
    uint8_t message2[128 + 64];

    memset(message1, 0x36, 128);
    memset(message2, 0x5C, 128);

    for (unsigned i = salt_length; i--;)
    {
        message1[i] = (uint8_t) (0x36 ^ salt[i]);
        message2[i] = (uint8_t) (0x5C ^ salt[i]);
    }

    memcpy(message1 + 128, data, data_length);

    sha512_hash(message2 + 128, message1, sizeof(message1));
    sha512_hash(out, message2, sizeof(message2));
#else
    uint8_t message1[128 + 256];
    uint8_t message2[128 + 64];

    memset(message1, 0x36, 128);
    memset(message2, 0x5C, 128);

    for (unsigned i = salt_length; i--;)
    {
        message1[i] = (uint8_t) (0x36 ^ salt[i]);
        message2[i] = (uint8_t) (0x5C ^ salt[i]);
    }

    memcpy(message1 + 128, data, data_length);

    sha512_hash(message2 + 128, message1, 128 + data_length);
    sha512_hash(out, message2, sizeof(message2));
#endif
}