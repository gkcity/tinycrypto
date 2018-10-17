/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   SrpServer.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include <stdint.h>
#include <string.h>
#include <tiny_random.h>
#include <tiny_log.h>
#include <tiny_malloc.h>
#include <sha/sha512.h>
#include <tiny_print_binary.h>
#include <bignum/tiny_bignum.h>
#include "SrpServer.h"
#include "srp_NG3072.h"
#include "srp_both.h"

#define TAG                 "SrpServer"

static tiny_mpi __g;
static tiny_mpi __N;

TINY_LOR
TinyRet SrpServer_Construct(SrpServer *thiz, const char *username, const char *password)
{
    TinyRet ret = TINY_RET_OK;

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(username, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(password, TINY_RET_E_ARG_NULL);

    do
    {
        memset(thiz, 0, sizeof(SrpServer));
        strncpy(thiz->username, username, USERNAME_LEN);
        strncpy(thiz->password, password, USERNAME_LEN);

        tiny_mpi_init(&__g);
        tiny_mpi_init(&__N);

        if (0 != tiny_mpi_lset(&__g, srp_G))
        {
            LOG_D(TAG, "mpi_lset FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != tiny_mpi_read_binary(&__N, (uint8_t *)srp_N, srp_N_LEN))
        {
            LOG_D(TAG, "mpi_read_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }
    } while (0);

    return ret;
}

TINY_LOR
void SrpServer_Dispose(SrpServer *thiz)
{
    RETURN_IF_FAIL(thiz);
    memset(thiz, 0, sizeof(SrpServer));

    tiny_mpi_free(&__g);
    tiny_mpi_free(&__N);
}

TINY_LOR
SrpServer *SrpServer_New(const char *username, const char *password)
{
    SrpServer *thiz = NULL;

    RETURN_VAL_IF_FAIL(username, NULL);
    RETURN_VAL_IF_FAIL(password, NULL);

    do
    {
        LOG_D(TAG, "SrpServer_New: [%s, %s]", username, password);

        thiz = (SrpServer *) tiny_malloc(sizeof(SrpServer));
        if (thiz == NULL)
        {
            LOG_D(TAG, "tiny_malloc FAILED.");
            break;
        }

        if (RET_FAILED(SrpServer_Construct(thiz, username, password)))
        {
            LOG_D(TAG, "SrpServer_Construct FAILED.");
            SrpServer_Delete(thiz);
            thiz = NULL;
            break;
        }
    } while (false);

    return thiz;
}

TINY_LOR
void SrpServer_Delete(SrpServer *thiz)
{
    RETURN_IF_FAIL(thiz);

    SrpServer_Dispose(thiz);
	tiny_free(thiz);
}

TINY_LOR
TinyRet SrpServer_Initialize_svbB(SrpServer *thiz)
{
    TinyRet ret = TINY_RET_OK;

    do
    {
        /**
         * 计算v, b, B的时间会比较长，可考虑:
         *
         * 1. 初始化时进行。
         * 2. 由于pin-code不能修改，可以考虑sdk静态生成。
         *
         * 在 POLARSSL_HAVE_LONGLONG 的情况下:
         *      计算 v 耗时: 14s
         *      计算 B 耗时: 7s
         *
         * 在　POLARSSL_HAVE_INT8 的情况下：
         *      计算 vB 耗时: 1分钟以上。
         *
         * 3. 8266 里集成了mbedtls.a, 可以考虑把IotCrypto拆分出去。
         */

        ret = SrpServer_generate_s(thiz);
        if (RET_FAILED(ret))
        {
            break;
        }

        ret = SrpServer_compute_v(thiz);
        if (RET_FAILED(ret))
        {
            break;
        }

        ret = SrpServer_generate_b(thiz);
        if (RET_FAILED(ret))
        {
            break;
        }

        ret = SrpServer_generate_B(thiz);
        if (RET_FAILED(ret))
        {
            break;
        }
    } while (0);

    return ret;
}

TINY_LOR
TinyRet SrpServer_Set_svbB(SrpServer *thiz, uint8_t s[salt_LEN], uint8_t v[v_LEN], uint8_t b[b_LEN], uint8_t B[B_LEN])
{
    memcpy(thiz->s, s, salt_LEN);
    memcpy(thiz->v, v, v_LEN);
    memcpy(thiz->b, b, b_LEN);
    memcpy(thiz->B, B, B_LEN);

    //    LOG_BINARY("s", thiz->srpServer->s, salt_LEN, false);
    //    LOG_BINARY("v", thiz->srpServer->v, v_LEN, false);
    //    LOG_BINARY("b", thiz->srpServer->b, b_LEN, false);
    //    LOG_BINARY("B", thiz->srpServer->B, B_LEN, false);

    return TINY_RET_OK;
}

#if SRP_TEST
TinyRet SrpServer_set_s_hex(SrpServer *thiz, const char *hex)
{
    TinyRet ret = TINY_RET_OK;
    tiny_mpi s;

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(hex, TINY_RET_E_ARG_NULL);

    LOG_D(TAG, "SrpServer_set_s_hex: %s", hex);

    tiny_mpi_init(&s);

    do
    {
        if (0 != tiny_mpi_read_string(&s, 16, hex))
        {
            LOG_D(TAG, "mpi_read_string FAILED.");
            ret =  TINY_RET_E_ARG_INVALID;
            break;
        }

        if (0 != tiny_mpi_write_binary(&s, thiz->s, salt_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED.");
            ret =  TINY_RET_E_ARG_INVALID;
            break;
        }
    } while (0);

    tiny_mpi_free(&s);

    return ret;
}

TinyRet SrpServer_set_b_hex(SrpServer *thiz, const char *hex)
{
    TinyRet ret = TINY_RET_OK;
    tiny_mpi b;

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(hex, TINY_RET_E_ARG_NULL);

    tiny_mpi_init(&b);

    do
    {
        if (0 != tiny_mpi_read_string(&b, 16, hex))
        {
            LOG_D(TAG, "mpi_read_string FAILED.");
            ret =  TINY_RET_E_ARG_INVALID;
            break;
        }

        if (0 != tiny_mpi_write_binary(&b, thiz->b, b_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED.");
            ret =  TINY_RET_E_ARG_INVALID;
            break;
        }
    } while (0);

    tiny_mpi_free(&b);

    return ret;
}

TinyRet SrpServer_set_A_hex(SrpServer *thiz, const char *hex)
{
    TinyRet ret = TINY_RET_OK;
    tiny_mpi A;

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(hex, TINY_RET_E_ARG_NULL);

    tiny_mpi_init(&A);

    do
    {
        uint8_t buf[A_LEN];

        memset(buf, 0, A_LEN);

        if (0 != tiny_mpi_read_string(&A, 16, hex))
        {
            LOG_D(TAG, "mpi_read_string FAILED.");
            ret =  TINY_RET_E_ARG_INVALID;
            break;
        }

        if (0 != tiny_mpi_write_binary(&A, buf, A_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED.");
            ret =  TINY_RET_E_ARG_INVALID;
            break;
        }

        ret = SrpServer_set_A(thiz, buf, A_LEN);
    } while (0);

    tiny_mpi_free(&A);

    return ret;
}
#endif

TINY_LOR
TinyRet SrpServer_set_A(SrpServer *thiz, const uint8_t *value, uint32_t len)
{
    TinyRet ret = TINY_RET_OK;

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(value, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(len == A_LEN, TINY_RET_E_ARG_NULL);

    LOG_MEM(TAG, "SrpServer_set_A");

    do
    {
        memcpy(thiz->A, value, A_LEN);

        ret = SrpServer_compute_u(thiz);
        if (RET_FAILED(ret))
        {
            break;
        }

        ret = SrpServer_compute_S(thiz);
        if (RET_FAILED(ret))
        {
            break;
        }

        ret = SrpServer_compute_K(thiz);
        if (RET_FAILED(ret))
        {
            break;
        }

        ret = SrpServer_compute_M1(thiz);
        if (RET_FAILED(ret))
        {
            break;
        }

        ret = SrpServer_compute_M2(thiz);
        if (RET_FAILED(ret))
        {
            break;
        }
    } while (0);

    return ret;
}

TINY_LOR
TinyRet SrpServer_generate_s(SrpServer *thiz)
{
    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);

    LOG_D(TAG, "SrpServer_generate_s");
    tiny_random_create(thiz->s, salt_LEN);

    return TINY_RET_OK;
}

TINY_LOR
TinyRet SrpServer_generate_b(SrpServer *thiz)
{
    LOG_D(TAG, "SrpServer_generate_b");

    tiny_random_create(thiz->b, b_LEN);

    return TINY_RET_OK;
}

TINY_LOR
TinyRet SrpServer_generate_B(SrpServer *thiz)
{
    TinyRet ret = TINY_RET_OK;
    tiny_mpi v;
    tiny_mpi k;
    tiny_mpi b;
    tiny_mpi B;
    tiny_mpi t1;
    tiny_mpi t2;

    LOG_D(TAG, "SrpServer_generate_B");

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);

    tiny_mpi_init(&v);
    tiny_mpi_init(&k);
    tiny_mpi_init(&b);
    tiny_mpi_init(&B);
    tiny_mpi_init(&t1);
    tiny_mpi_init(&t2);

    do
    {
        // 'b'
        if (0 != tiny_mpi_read_binary(&b, thiz->b, b_LEN))
        {
            LOG_D(TAG, "mpi_read_binary FAILED: bv");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        // t1 = g^b % N
        if (0 != tiny_mpi_exp_mod(&t1, &__g, &b, &__N, NULL))
        {
            LOG_D(TAG, "mpi_exp_mod FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        // 'v'
        if (0 != tiny_mpi_read_binary(&v, thiz->v, v_LEN))
        {
            LOG_D(TAG, "mpi_read_binary FAILED: v");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        // 'k'
        if (0 != tiny_mpi_read_binary(&k, srp_N_G_hash, srp_HASH_LEN))
        {
            LOG_D(TAG, "mpi_read_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        // t2 = v * k
        if (0 != tiny_mpi_mul_mpi(&t2, &v, &k))
        {
            LOG_D(TAG, "mpi_mul_mpi FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        // B = (t1 + t2) & N;
        if (0 != tiny_mpi_add_mpi(&B, &t1, &t2))
        {
            LOG_D(TAG, "mpi_mod_mpi FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != tiny_mpi_mod_mpi(&B, &B, &__N))
        {
            LOG_D(TAG, "mpi_mod_mpi FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != tiny_mpi_write_binary(&B, thiz->B, B_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }
    } while (0);

    tiny_mpi_free(&v);
    tiny_mpi_free(&k);
    tiny_mpi_free(&b);
    tiny_mpi_free(&B);
    tiny_mpi_free(&t1);
    tiny_mpi_free(&t2);

    return ret;
}

TINY_LOR
TinyRet SrpServer_compute_v(SrpServer *thiz)
{
    TinyRet ret = TINY_RET_OK;
    tiny_mpi x;
    tiny_mpi v;
    tiny_mpi tmp;

    LOG_D(TAG, "SrpServer_compute_v");

    tiny_mpi_init(&x);
    tiny_mpi_init(&v);
    tiny_mpi_init(&tmp);

    do
    {
        // Calculate 'x' = H(s | H(I | ":" | P))
        ret = srp_compute_x(thiz->username, thiz->password, thiz->s, thiz->x);
        if (RET_FAILED(ret))
        {
            LOG_D(TAG, "srp_compute_x FAILED.");
            break;
        }

        if (0 != tiny_mpi_read_binary(&x, thiz->x, srp_HASH_LEN))
        {
            LOG_D(TAG, "mpi_read_binary FAILED: x");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        // Calculate 'v' = g ^ x mod N
        if (0 != tiny_mpi_exp_mod(&v, &__g, &x, &__N, &tmp))
        {
            LOG_D(TAG, "mpi_exp_mod FAILED: v");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != tiny_mpi_write_binary(&v, thiz->v, v_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED: v");
            ret = TINY_RET_E_INTERNAL;
            break;
        }
    } while (0);

    tiny_mpi_free(&x);
    tiny_mpi_free(&v);
    tiny_mpi_free(&tmp);

    return ret;
}

TINY_LOR
TinyRet SrpServer_compute_u(SrpServer *thiz)
{
    TinyRet ret = TINY_RET_OK;
    tiny_mpi u;

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);

    tiny_mpi_init(&u);

    do
    {
        // u = H(A | B)
        uint8_t AB_hash[srp_HASH_LEN];
        uint8_t message[A_LEN + B_LEN];

        memcpy(message, thiz->A, A_LEN);
        memcpy(message + A_LEN, thiz->B, B_LEN);

        sha512_hash(AB_hash, message, A_LEN + B_LEN);

        if (0 != tiny_mpi_read_binary(&u, AB_hash, srp_HASH_LEN))
        {
            LOG_D(TAG, "mpi_read_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != tiny_mpi_write_binary(&u, thiz->u, u_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }
    } while (0);

    tiny_mpi_free(&u);

    return ret;
}

TINY_LOR
TinyRet SrpServer_compute_S(SrpServer *thiz)
{
    TinyRet ret = TINY_RET_OK;
    tiny_mpi S;
    tiny_mpi A;
    tiny_mpi v;
    tiny_mpi u;
    tiny_mpi b;

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);

    tiny_mpi_init(&S);
    tiny_mpi_init(&A);
    tiny_mpi_init(&v);
    tiny_mpi_init(&u);
    tiny_mpi_init(&b);

    // S = (A * v^u mod N) ^ b mod N

    LOG_I(TAG, "S = (A * v^u mod N) ^ b mod N");

    do
    {
        int result = 0;

        tiny_mpi_read_binary(&A, thiz->A, A_LEN);
        tiny_mpi_read_binary(&v, thiz->v, v_LEN);
        tiny_mpi_read_binary(&u, thiz->u, u_LEN);
        tiny_mpi_read_binary(&b, thiz->b, b_LEN);

        //LOG_BINARY("A", thiz->A, A_LEN, false);
        //LOG_BINARY("v", thiz->v, v_LEN, false);
        //LOG_BINARY("u", thiz->u, u_LEN, false);
        //LOG_BINARY("b", thiz->b, b_LEN, false);

        LOG_I(TAG, "S1 = v ^ u %% N");

        // S1 = v ^ u % N
        result = tiny_mpi_exp_mod(&S, &v, &u, &__N, NULL);
        if (0 != result)
        {
            LOG_E(TAG, "tiny_mpi_exp_mod FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        LOG_I(TAG, "S2 = S1 * A");

        // S2 = S1 * A
        if (0 != tiny_mpi_mul_mpi(&S, &S, &A))
        {
            LOG_E(TAG, "tiny_mpi_mul_mpi FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        LOG_I(TAG, "S = S2 ^ b %% N");

        // S = S2 ^ b % N
        if (0 != tiny_mpi_exp_mod(&S, &S, &b, &__N, NULL))
        {
            LOG_E(TAG, "tiny_mpi_exp_mod FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != tiny_mpi_write_binary(&S, thiz->S, S_LEN))
        {
            LOG_E(TAG, "tiny_mpi_write_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        //LOG_BINARY("S", thiz->S, S_LEN, false);
    } while (0);

    tiny_mpi_free(&S);
    tiny_mpi_free(&A);
    tiny_mpi_free(&v);
    tiny_mpi_free(&u);
    tiny_mpi_free(&b);

    return ret;
}

TINY_LOR
TinyRet SrpServer_compute_K(SrpServer *thiz)
{
    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);

    // K = H(S);
    sha512_hash(thiz->K, thiz->S, S_LEN);

    return TINY_RET_OK;
}

TINY_LOR
TinyRet SrpServer_compute_M1(SrpServer *thiz)
{
    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);

    // M1 = H(H(N) xor H(g) | H(username) | s | A | B | K)
    return srp_compute_M1(thiz->username, thiz->s, thiz->A, thiz->B, thiz->K, thiz->M1);
}

TINY_LOR
TinyRet SrpServer_compute_M2(SrpServer *thiz)
{
    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);

    // M2 = H(A | M1 | K)
    return srp_compute_M2(thiz->A, thiz->M1, thiz->K, thiz->M2);
}


TINY_LOR
TinyRet SrpServer_Verify(SrpServer *thiz, const uint8_t *A, uint32_t len, const uint8_t *M1, uint32_t size)
{
    TinyRet ret = TINY_RET_OK;

    do
    {
        ret = SrpServer_set_A(thiz, A, len);
        if (RET_FAILED(ret))
        {
            LOG_D(TAG, "SrpServer_set_A FAILED");
            break;
        }

//        LOG_BINARY("A", A, A_len, false);
//        LOG_BINARY("u", thiz->srpServer->u, u_LEN, false);
//        LOG_BINARY("S", thiz->srpServer->S, S_LEN, false);
//        LOG_BINARY("K", thiz->srpServer->K, K_LEN, false);
//        LOG_BINARY("M1", thiz->srpServer->M1, M1_LEN, false);
//        LOG_BINARY("M2", thiz->srpServer->M2, M2_LEN, false);
//        LOG_BINARY("computed M1", thiz->srpServer->M1, M1_LEN, false);
//        LOG_BINARY("clientM1", clientM1, clientM1_len, false);

        if (memcmp(M1, thiz->M1, M1_LEN) != 0)
        {
            LOG_D(TAG, "clientM1 NOT EQUALS M1");
            ret = TINY_RET_E_ARG_INVALID;
            break;
        }
    } while (false);

    return ret;
}

TINY_LOR
uint8_t * SrpServer_GetSalt(SrpServer *thiz)
{
    return thiz->s;
}

TINY_LOR
uint8_t * SrpServer_GetB(SrpServer *thiz)
{
    return thiz->B;
}

TINY_LOR
uint8_t * SrpServer_GetM2(SrpServer *thiz)
{
    return thiz->M2;
}

TINY_LOR
uint8_t * SrpServer_GetK(SrpServer *thiz)
{
    return thiz->K;
}
