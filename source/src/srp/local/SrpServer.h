/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   SrpServer.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __SRP_SERVER_H__
#define __SRP_SERVER_H__

#include <tiny_base.h>
#include <hap_api.h>
#include "srp/srp_define.h"

TINY_BEGIN_DECLS

#define SRP_TEST 0

struct _SrpServer
{
    char username[USERNAME_LEN];
    char password[PASSWORD_LEN];
    uint8_t x[srp_HASH_LEN];
    uint8_t s[salt_LEN];
    uint8_t v[v_LEN];
    uint8_t b[b_LEN];
    uint8_t B[B_LEN];
    uint8_t A[A_LEN];
    uint8_t u[u_LEN];
    uint8_t S[S_LEN];
    uint8_t K[K_LEN];
    uint8_t M1[M1_LEN];
    uint8_t M2[M2_LEN];
};

typedef struct _SrpServer SrpServer;

HAP_API
TINY_LOR
SrpServer *SrpServer_New(const char *username, const char *password);

HAP_API
TINY_LOR
TinyRet SrpServer_Construct(SrpServer *thiz, const char *username, const char *password);

HAP_API
TINY_LOR
void SrpServer_Delete(SrpServer *thiz);

HAP_API
TINY_LOR
void SrpServer_Dispose(SrpServer *thiz);

HAP_API
TINY_LOR
TinyRet SrpServer_Initialize_svbB(SrpServer *thiz);

HAP_API
TINY_LOR
TinyRet SrpServer_Set_svbB(SrpServer *thiz, uint8_t s[salt_LEN], uint8_t v[v_LEN], uint8_t b[b_LEN], uint8_t B[B_LEN]);

#if SRP_TEST
HAP_API TinyRet SrpServer_set_s_hex(SrpServer *thiz, const char *hex);
HAP_API TinyRet SrpServer_set_b_hex(SrpServer *thiz, const char *hex);
HAP_API TinyRet SrpServer_set_A_hex(SrpServer *thiz, const char *hex);
#endif

HAP_API
TINY_LOR
TinyRet SrpServer_generate_s(SrpServer *thiz);

HAP_API
TINY_LOR
TinyRet SrpServer_compute_v(SrpServer *thiz);

HAP_API
TINY_LOR
TinyRet SrpServer_generate_b(SrpServer *thiz);

HAP_API
TINY_LOR
TinyRet SrpServer_generate_B(SrpServer *thiz);

HAP_API
TINY_LOR
TinyRet SrpServer_set_A(SrpServer *thiz, const uint8_t *value, uint32_t len);

HAP_API
TINY_LOR
TinyRet SrpServer_compute_u(SrpServer *thiz);

HAP_API
TINY_LOR
TinyRet SrpServer_compute_S(SrpServer *thiz);

HAP_API
TINY_LOR
TinyRet SrpServer_compute_K(SrpServer *thiz);

HAP_API
TINY_LOR
TinyRet SrpServer_compute_M1(SrpServer *thiz);

HAP_API
TINY_LOR
TinyRet SrpServer_compute_M2(SrpServer *thiz);

HAP_API
TINY_LOR
TinyRet SrpServer_Verify(SrpServer *thiz, const uint8_t *A, uint32_t len, const uint8_t *M1, uint32_t size);

HAP_API
TINY_LOR
uint8_t * SrpServer_GetSalt(SrpServer *thiz);

HAP_API
TINY_LOR
uint8_t * SrpServer_GetB(SrpServer *thiz);

HAP_API
TINY_LOR
uint8_t * SrpServer_GetM2(SrpServer *thiz);

HAP_API
TINY_LOR
uint8_t * SrpServer_GetK(SrpServer *thiz);


TINY_END_DECLS

#endif /* __SRP_SERVER_H__ */