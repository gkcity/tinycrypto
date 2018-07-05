/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   base64.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include <tiny_malloc.h>
#include <ctype.h>
#include "base64.h"

/* aaaack but it's fast and const should make it shared text page. */
static const unsigned char pr2six[256] =
        {
                /* ASCII table */
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
                52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
                64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
                64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
        };

uint32_t base64_decode_out_length(const char *string)
{
    uint32_t nbytesdecoded;
    register const unsigned char *bufin;
    register uint32_t nprbytes;

    bufin = (const unsigned char *) string;
    while (pr2six[*(bufin++)] <= 63)
    {
    }

    nprbytes = (uint32_t)(bufin - (const unsigned char *) string) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    return nbytesdecoded + 1;
}

uint32_t base64_decode(const char *bufcoded, uint8_t *bufplain)
{
    uint32_t nbytesdecoded;
    register const unsigned char *bufin;
    register unsigned char *bufout;
    register uint32_t nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63)
    {
    }

    nprbytes = (uint32_t)(bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufout = (unsigned char *) bufplain;
    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 4)
    {
        *(bufout++) = pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4;
        *(bufout++) = pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2;
        *(bufout++) = pr2six[bufin[2]] << 6 | pr2six[bufin[3]];
        bufin += 4;
        nprbytes -= 4;
    }

    /* Note: (nprbytes == 1) would be an error, so just ingore that case */
    if (nprbytes > 1)
    {
        *(bufout++) = pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4;
    }
    if (nprbytes > 2)
    {
        *(bufout++) = pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2;
    }
    if (nprbytes > 3)
    {
        *(bufout++) = pr2six[bufin[2]] << 6 | pr2six[bufin[3]];
    }

    *(bufout++) = '\0';
    nbytesdecoded -= (4 - nprbytes) & 3;

    return nbytesdecoded;
}

static const char basis_64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

uint32_t base64_encode_out_length(int bytesLength)
{
    return ((bytesLength + 2) / 3 * 4) + 1;
}

uint32_t base64_encode(const uint8_t *bytes, int length, char *out)
{
    int i = 0;
    char *p = out;

    for (i = 0; i < length - 2; i += 3)
    {
        *p++ = basis_64[(bytes[i] >> 2) & 0x3F];
        *p++ = basis_64[((bytes[i] & 0x3) << 4) | ((bytes[i + 1] & 0xF0) >> 4)];
        *p++ = basis_64[((bytes[i + 1] & 0xF) << 2) | ((bytes[i + 2] & 0xC0) >> 6)];
        *p++ = basis_64[bytes[i + 2] & 0x3F];
    }

    if (i < length)
    {
        *p++ = basis_64[(bytes[i] >> 2) & 0x3F];
        if (i == (length - 1))
        {
            *p++ = basis_64[((bytes[i] & 0x3) << 4)];
            *p++ = '=';
        }
        else
        {
            *p++ = basis_64[((bytes[i] & 0x3) << 4) | ((bytes[i + 1] & 0xF0) >> 4)];
            *p++ = basis_64[((bytes[i + 1] & 0xF) << 2)];
        }

        *p++ = '=';
    }

    *p++ = '\0';

    return (uint32_t)(p - out);
}