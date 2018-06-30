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
		message1[i] = (uint8_t)(0x36 ^ salt[i]);
		message2[i] = (uint8_t)(0x5C ^ salt[i]);
	}

	memcpy(message1 + 128, data, data_length);

	sha512_hash(message2 + 128, message1, 128 + data_length);
	sha512_hash(out, message2, sizeof(message2));
#endif
}