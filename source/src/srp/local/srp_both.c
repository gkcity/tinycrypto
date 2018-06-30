/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   srp_both.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include <sha/sha512.h>
#include <tiny_snprintf.h>
#include "srp_both.h"

// x = H(s | H(I | ":" | P))
TINY_LOR
TinyRet srp_compute_x(const char username[USERNAME_LEN],
                      const char password[PASSWORD_LEN],
                      const uint8_t salt[salt_LEN],
                      uint8_t x[srp_HASH_LEN])
{
    char up[USERNAME_LEN + 1 + PASSWORD_LEN];
    uint8_t message[salt_LEN + 64];

    memset(up, 0, USERNAME_LEN + 1 + PASSWORD_LEN);
    tiny_snprintf(up, USERNAME_LEN + 1 + PASSWORD_LEN, "%s:%s", username, password);

    memcpy(message, salt, salt_LEN);
    sha512_hash(message + salt_LEN, (const unsigned char *) up, strlen(up));
    sha512_hash(x, message, sizeof(message));

    return TINY_RET_OK;
}

// M1 = H(H(N) xor H(g) | H(username) | s | A | B | K)
TINY_LOR
TinyRet srp_compute_M1(const char username[USERNAME_LEN],
                       const uint8_t salt[salt_LEN],
                       const uint8_t A[A_LEN],
                       const uint8_t B[B_LEN],
                       const uint8_t K[K_LEN],
                       uint8_t M1[M1_LEN])
{
    uint8_t message[srp_HASH_LEN + 64 + salt_LEN + A_LEN + B_LEN + K_LEN];
    memcpy(message, srp_hash_N_xor_hash_g, srp_HASH_LEN);
    sha512_hash(message + srp_HASH_LEN, (const unsigned char *)username, strlen(username));
    memcpy(message + srp_HASH_LEN + 64, salt, salt_LEN);

    if (A[0] != 0)
    {
        memcpy(message + srp_HASH_LEN + 64 + salt_LEN, A, A_LEN);

        if (B[0] != 0)
        {
            memcpy(message + srp_HASH_LEN + 64 + salt_LEN + A_LEN, B, B_LEN);
            memcpy(message + srp_HASH_LEN + 64 + salt_LEN + A_LEN + B_LEN, K, K_LEN);
            sha512_hash(M1, message, sizeof(message));
        }
        else
        {
            memcpy(message + srp_HASH_LEN + 64 + salt_LEN + A_LEN, B + 1, B_LEN - 1);
            memcpy(message + srp_HASH_LEN + 64 + salt_LEN + A_LEN + B_LEN - 1, K, K_LEN);
            sha512_hash(M1, message, sizeof(message) - 1);
        }
    }
    else
    {
        memcpy(message + srp_HASH_LEN + 64 + salt_LEN, A + 1, A_LEN - 1);

        if (B[0] != 0)
        {
            memcpy(message + srp_HASH_LEN + 64 + salt_LEN + A_LEN - 1, B, B_LEN);
            memcpy(message + srp_HASH_LEN + 64 + salt_LEN + A_LEN - 1 + B_LEN, K, K_LEN);
            sha512_hash(M1, message, sizeof(message));
        }
        else
        {
            memcpy(message + srp_HASH_LEN + 64 + salt_LEN + A_LEN - 1, B + 1, B_LEN - 1);
            memcpy(message + srp_HASH_LEN + 64 + salt_LEN + A_LEN - 1 + B_LEN - 1, K, K_LEN);
            sha512_hash(M1, message, sizeof(message) - 1 - 1);
        }
    }

    return TINY_RET_OK;
}

TINY_LOR
TinyRet srp_compute_M2(const uint8_t A[A_LEN],
                       const uint8_t M1[M1_LEN],
                       const uint8_t K[K_LEN],
                       uint8_t M2[M2_LEN])
{
    uint8_t message[A_LEN + M1_LEN + K_LEN];
    memcpy(message, A, A_LEN);
    memcpy(message + A_LEN, M1, M1_LEN);
    memcpy(message + A_LEN + M1_LEN, K, K_LEN);
    sha512_hash(M2, message, sizeof(message));

    return TINY_RET_OK;
}