/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   chacha20poly1305.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include <chacha20/ChaCha20.h>
#include <poly1305/Poly1305.h>
#include <tiny_log.h>
#include "chacha20poly1305.h"

#define TAG "chacha20poly1305"

TINY_LOR
static void poly1305_compute_mac(const uint8_t key[32],
                                 const uint8_t *buf,
                                 uint32_t bufLength,
                                 const uint8_t *additional,
                                 uint32_t addLength,
                                 uint8_t mac[16])
{
    Poly1305 p;
    uint8_t len = 0;

    memset(&p, 0, sizeof(p));
    Poly1305_Initialize(&p, key);

    uint8_t waste[16];
    memset(waste, 0, 16);

    if (additional != NULL)
    {
        Poly1305_Update(&p, additional, addLength);
        Poly1305_Update(&p, waste, 16 - addLength);
        Poly1305_Update(&p, buf, bufLength);
    }
    else
    {
        Poly1305_Update(&p, buf, bufLength);
    }

    if (bufLength % 16 > 0)
    {
        Poly1305_Update(&p, waste, 16 - (bufLength % 16));
    }

    len = (uint8_t) addLength;
    Poly1305_Update(&p, (const unsigned char *) &len, 1);
    Poly1305_Update(&p, (const unsigned char *) &waste, 7);

    len = (uint8_t) bufLength;
    Poly1305_Update(&p, (const unsigned char *) &len, 1);

    len = (uint8_t) (bufLength / 256);
    Poly1305_Update(&p, (const unsigned char *) &len, 1);
    Poly1305_Update(&p, (const unsigned char *) &waste, 6);

    Poly1305_Finish(&p, mac);
}

TINY_LOR
TinyRet chacha20poly1305_decrypt(const uint8_t *key,
                                 uint32_t keyLength,
                                 const uint8_t nonce[8],
                                 const uint8_t *ciphertext,
                                 uint32_t ciphertextLength,
                                 const uint8_t mac[16],
                                 uint8_t *plaintext,
                                 const uint8_t *additional,
                                 uint32_t additionalLength)
{
    ChaCha20 cc;
    uint8_t temp[64];
    uint8_t temp2[64];
    uint8_t computedMAC[16];

    memset(&cc, 0, sizeof(ChaCha20));
    memset(&temp, 0, 64);
    memset(&temp2, 0, 64);
    memset(&computedMAC, 0, 16);

    // init key
    ChaCha20_Initialize(&cc, key, keyLength, nonce);

    // verify MAC
    ChaCha20_Encrypt(&cc, temp, temp2, 64);
    poly1305_compute_mac(temp2, ciphertext, ciphertextLength, additional, additionalLength, computedMAC);
    if (memcmp(computedMAC, mac, 16) != 0)
    {
        LOG_D(TAG, "computedMAC != MAC\n");
        return TINY_RET_E_ARG_INVALID;
    }

    // decode
    ChaCha20_Decrypt(&cc, ciphertext, plaintext, ciphertextLength);

    return TINY_RET_OK;
}

TINY_LOR
void chacha20poly1305_encrypt(const uint8_t *key,
                              uint32_t keyLength,
                              const uint8_t nonce[8],
                              const uint8_t *plaintext,
                              uint32_t plaintextLength,
                              uint8_t *ciphertext,
                              uint8_t mac[16],
                              const uint8_t *additional,
                              uint32_t additionalLength)
{
    ChaCha20 cc;
    uint8_t buffer[64];
    uint8_t KK[64];

    memset(&cc, 0, sizeof(ChaCha20));
    memset(&buffer, 0, 64);
    memset(&KK, 0, 64);

    // init key
    ChaCha20_Initialize(&cc, key, keyLength, nonce);
    ChaCha20_Encrypt(&cc, buffer, KK, 64);

    // encode
    ChaCha20_Encrypt(&cc, plaintext, ciphertext, plaintextLength);

    // compute MAC
    poly1305_compute_mac(KK, ciphertext, plaintextLength, additional, additionalLength, mac);
}