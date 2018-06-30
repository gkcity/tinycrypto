/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   SrpClient.c
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#include "SrpClient.h"
#include "srp_both.h"
#include "bignum/polarssl/bignum.h"
#include "tiny_log_binary.h"
#include <tiny_log.h>
#include <tiny_malloc.h>
#include <sha/sha512.h>

#define TAG                 "SrpClient"

struct _SrpClient
{
    char username[USERNAME_LEN];
    char password[PASSWORD_LEN];
    mpi g;
    mpi N;
    mpi s;
    mpi a;
    mpi x;
    mpi A;
    mpi B;
    mpi u;
    mpi S;
    mpi K;
    mpi M1;
    mpi M2;
};

static TinyRet _SrpClient_Construct(SrpClient *thiz, const char *username, const char *password)
{
    TinyRet ret = TINY_RET_OK;

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(username, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(password, TINY_RET_E_ARG_NULL);

    do
    {
        memset(thiz, 0, sizeof(SrpClient));
        strncpy(thiz->username, username, USERNAME_LEN);
        strncpy(thiz->password, password, USERNAME_LEN);
        mpi_init(&thiz->g);
        mpi_init(&thiz->N);
        mpi_init(&thiz->s);
        mpi_init(&thiz->a);
        mpi_init(&thiz->x);
        mpi_init(&thiz->A);
        mpi_init(&thiz->B);
        mpi_init(&thiz->u);
        mpi_init(&thiz->S);
        mpi_init(&thiz->K);
        mpi_init(&thiz->M1);
        mpi_init(&thiz->M2);

        if (0 != mpi_lset(&thiz->g, srp_G))
        {
            LOG_D(TAG, "mpi_lset FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != mpi_read_binary(&thiz->N, (uint8_t *) srp_N, srp_N_LEN))
        {
            LOG_D(TAG, "mpi_read_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }
    } while (0);

    return ret;
}

static void SrpClient_Dispose(SrpClient *thiz)
{
    RETURN_IF_FAIL(thiz);

    mpi_free(&thiz->g);
    mpi_free(&thiz->N);
    mpi_free(&thiz->s);
    mpi_free(&thiz->a);
    mpi_free(&thiz->x);
    mpi_free(&thiz->A);
    mpi_free(&thiz->B);
    mpi_free(&thiz->u);
    mpi_free(&thiz->S);
    mpi_free(&thiz->K);
    mpi_free(&thiz->M1);
    mpi_free(&thiz->M2);

    memset(thiz, 0, sizeof(SrpClient));
}

SrpClient *SrpClient_New(const char *username, const char *password)
{
    SrpClient *thiz = NULL;

    do
    {
        thiz = (SrpClient *) tiny_malloc(sizeof(SrpClient));
        if (thiz == NULL)
        {
            LOG_D(TAG, "tiny_malloc FAILED.");
            break;
        }

        if (RET_FAILED(_SrpClient_Construct(thiz, username, password)))
        {
            LOG_D(TAG, "SrpServer_Construct FAILED.");
            SrpClient_Delete(thiz);
            thiz = NULL;
            break;
        }
    } while (false);

    return thiz;
}

void SrpClient_Delete(SrpClient *thiz)
{
    RETURN_IF_FAIL(thiz);

    SrpClient_Dispose(thiz);
    tiny_free(thiz);
}

TinyRet SrpClient_set_s(SrpClient *thiz, const uint8_t *s, size_t s_len)
{
    TinyRet ret = TINY_RET_OK;

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(s, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(s_len, TINY_RET_E_ARG_NULL);

    do
    {
//        uint8_t salt[salt_LEN];
        uint8_t x_hash[srp_HASH_LEN];

#if 0
        if (0 != mpi_read_string(&thiz->s, 16, s_hex))
        {
            LOG_E(TAG, "Failed to set s");
            ret = TINY_RET_E_ARG_INVALID;
            break;
        }

        if (0 != mpi_write_binary(&thiz->s, salt, salt_LEN))
        {
            LOG_D(TAG, "mpi_write_string FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }
#else
        if (0 != mpi_read_binary(&thiz->s, s, s_len))
        {
            LOG_E(TAG, "Failed to set s");
            ret = TINY_RET_E_ARG_INVALID;
            break;
        }
#endif

        // Calculate 'x' = H(s | H(I | ":" | P))
        ret = srp_compute_x(thiz->username, thiz->password, s, x_hash);
        if (RET_FAILED(ret))
        {
            LOG_D(TAG, "srp_compute_x FAILED.");
            break;
        }

        print_binary("x", x_hash, 64);

        if (0 != mpi_read_binary(&thiz->x, x_hash, srp_HASH_LEN))
        {
            LOG_D(TAG, "mpi_read_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }
    } while (false);

    return ret;
}

#if 0
TinyRet SrpClient_generate_A(SrpClient *thiz, char *A_hex, size_t *A_len)
{
    TinyRet ret = TINY_RET_OK;
    mpi tmp;

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(A_hex, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(A_len, TINY_RET_E_ARG_NULL);

    mpi_init(&tmp);

    do
    {
        uint8_t a[a_LEN];

        random_create(a, b_LEN);

        if (0 != mpi_read_binary(&thiz->a, a, a_LEN))
        {
            LOG_D(TAG, "mpi_read_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        // A = g ^ a mod N
        if (0 != mpi_exp_mod(&thiz->A, &thiz->g, &thiz->a, &thiz->N, &tmp))
        {
            LOG_D(TAG, "mpi_exp_mod FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != mpi_write_string(&thiz->A, 16, A_hex, A_len))
        {
            LOG_D(TAG, "mpi_write_string FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }
    } while (0);

    mpi_free(&tmp);

    return ret;
}
#else
TinyRet SrpClient_generate_A(SrpClient *thiz, uint8_t *A, size_t *A_len)
{
    const char *_a = "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393";
    const char *_A = "FAB6F5D2615D1E323512E7991CC37443F487DA604CA8C9230FCB04E541DCE628"
            "0B27CA4680B0374F179DC3BDC7553FE62459798C701AD864A91390A28C93B644"
            "ADBF9C00745B942B79F9012A21B9B78782319D83A1F8362866FBD6F46BFC0DDB"
            "2E1AB6E4B45A9906B82E37F05D6F97F6A3EB6E182079759C4F6847837B62321A"
            "C1B4FA68641FCB4BB98DD697A0C73641385F4BAB25B793584CC39FC8D48D4BD8"
            "67A9A3C10F8EA12170268E34FE3BBE6FF89998D60DA2F3E4283CBEC1393D52AF"
            "724A57230C604E9FBCE583D7613E6BFFD67596AD121A8707EEC4694495703368"
            "6A155F644D5C5863B48F61BDBF19A53EAB6DAD0A186B8C152E5F5D8CAD4B0EF8"
            "AA4EA5008834C3CD342E5E0F167AD04592CD8BD279639398EF9E114DFAAAB919"
            "E14E850989224DDD98576D79385D2210902E9F9B1F2D86CFA47EE244635465F7"
            "1058421A0184BE51DD10CC9D079E6F1604E7AA9B7CF7883C7D4CE12B06EBE160"
            "81E23F27A231D18432D7D1BB55C28AE21FFCF005F57528D15A88881BB3BBB7FE";

    TinyRet ret = TINY_RET_OK;

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(A, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(A_len, TINY_RET_E_ARG_NULL);

    do
    {
        if (0 != mpi_read_string(&thiz->a, 16, _a))
        {
            LOG_D(TAG, "mpi_read_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != mpi_read_string(&thiz->A, 16, _A))
        {
            LOG_D(TAG, "mpi_read_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (*A_len < B_LEN)
        {
            LOG_D(TAG, "len is too short");
            ret = TINY_RET_E_ARG_INVALID;
            break;
        }

        if (0 != mpi_write_binary(&thiz->A, A, A_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        *A_len = A_LEN;
    } while (false);

    return ret;
}
#endif

TinyRet SrpClient_compute_u(SrpClient *thiz, const uint8_t *B, size_t B_len, uint8_t *u, size_t *u_len)
{
    TinyRet ret = TINY_RET_OK;

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(B, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(B_len, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(u, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(u_len, TINY_RET_E_ARG_NULL);

    do
    {
        uint8_t A[A_LEN];

        if (B_len != B_LEN)
        {
            LOG_D(TAG, "B_len invalid.");
            ret = TINY_RET_E_ARG_INVALID;
            break;
        }

        if (0 != mpi_read_binary(&thiz->B, B, B_len))
        {
            LOG_D(TAG, "mpi_read_string FAILED.");
            ret = TINY_RET_E_ARG_INVALID;
            break;
        }

        if (0 != mpi_write_binary(&thiz->A, A, A_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        // u = H(A | B)
        {
            uint8_t message[A_LEN + B_LEN];
            memcpy(message, A, A_LEN);
            memcpy(message + A_LEN, B, B_LEN);
            sha512_hash(message, message, A_LEN + B_LEN);
            if (0 != mpi_read_binary(&thiz->u, message, 64))
            {
                LOG_D(TAG, "mpi_read_binary FAILED.");
                ret = TINY_RET_E_INTERNAL;
                break;
            }
        }

        if (*u_len < u_LEN)
        {
            LOG_D(TAG, "len is too short");
            ret = TINY_RET_E_ARG_INVALID;
            break;
        }

        if (0 != mpi_write_binary(&thiz->u, u, u_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        *u_len = u_LEN;
    } while (false);

    return ret;
}

TinyRet SrpClient_compute_S(SrpClient *thiz, uint8_t *S, size_t *S_len)
{
    TinyRet ret = TINY_RET_OK;
    mpi k;
    mpi tmp;

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(S, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(S_len, TINY_RET_E_ARG_NULL);

    // S = (B - k * g^x) ^ (a + u * x) % N

    mpi_init(&k);
    mpi_init(&tmp);

    do
    {
        // S = g ^ x mod N
        if (0 != mpi_exp_mod(&thiz->S, &thiz->g, &thiz->x, &thiz->N, NULL))
        {
            LOG_D(TAG, "mpi_exp_mod FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        // Calculate 'k'
        if (0 != mpi_read_binary(&k, srp_N_G_hash, srp_HASH_LEN))
        {
            LOG_D(TAG, "mpi_read_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        // S = k * S
        if (0 != mpi_mul_mpi(&thiz->S, &k, &thiz->S))
        {
            LOG_D(TAG, "mpi_mul_mpi FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        // S = S mod N
        if (0 != mpi_mod_mpi(&thiz->S, &thiz->S, &thiz->N))
        {
            LOG_D(TAG, "mpi_mod_mpi FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        // S = B - S
        if (0 != mpi_sub_mpi(&thiz->S, &thiz->B, &thiz->S))
        {
            LOG_D(TAG, "mpi_sub_mpi FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        // tmp = u * x
        if (0 != mpi_mul_mpi(&tmp, &thiz->u, &thiz->x))
        {
            LOG_D(TAG, "mpi_mul_mpi FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        // tmp = a + tmp
        if (0 != mpi_add_mpi(&tmp, &thiz->a, &tmp))
        {
            LOG_D(TAG, "mpi_add_mpi FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        // S = S ^ tmp % N
        if (0 != mpi_exp_mod(&thiz->S, &thiz->S, &tmp, &thiz->N, NULL))
        {
            LOG_D(TAG, "mpi_exp_mod FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (*S_len < S_LEN)
        {
            LOG_D(TAG, "len is too short");
            ret = TINY_RET_E_ARG_INVALID;
            break;
        }

        if (0 != mpi_write_binary(&thiz->S, S, S_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        *S_len = S_LEN;
    } while (false);

    mpi_free(&tmp);

    return ret;
}

TinyRet SrpClient_compute_K(SrpClient *thiz, uint8_t *K, size_t *K_len)
{
    TinyRet ret = TINY_RET_OK;

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(K, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(K_len, TINY_RET_E_ARG_NULL);

    // K = H(S);

    do
    {
        uint8_t S[S_LEN];

        if (0 != mpi_write_binary(&thiz->S, S, S_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        sha512_hash(K, S, S_LEN);

        if (0 != mpi_read_binary(&thiz->K, K, K_LEN))
        {
            LOG_D(TAG, "mpi_read_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (*K_len < K_LEN)
        {
            LOG_D(TAG, "len is too short");
            ret = TINY_RET_E_ARG_INVALID;
            break;
        }

        if (0 != mpi_write_binary(&thiz->K, K, K_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        *K_len = K_LEN;
    } while (false);

    return ret;
}

TinyRet SrpClient_compute_M1(SrpClient *thiz, uint8_t *M1, size_t *M1_len)
{
    TinyRet ret = TINY_RET_OK;

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(M1, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(M1_len, TINY_RET_E_ARG_NULL);

    // M1 = H(username | s | A | B | K)

    do
    {
        uint8_t salt[salt_LEN];
        uint8_t A[A_LEN];
        uint8_t B[B_LEN];
        uint8_t K[K_LEN];

        if (0 != mpi_write_binary(&thiz->s, salt, salt_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != mpi_write_binary(&thiz->A, A, A_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != mpi_write_binary(&thiz->B, B, B_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != mpi_write_binary(&thiz->K, K, K_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        ret = srp_compute_M1(thiz->username, salt, A, B, K, M1);
        if (RET_FAILED(ret))
        {
            LOG_D(TAG, "srp_compute_M1 FAILED.");
            break;
        }

        if (0 != mpi_read_binary(&thiz->M1, M1, M1_LEN))
        {
            LOG_D(TAG, "mpi_read_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (*M1_len < M1_LEN)
        {
            LOG_D(TAG, "len is too short");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        *M1_len = M1_LEN;
    } while (false);

    return ret;
}

TinyRet SrpClient_compute_M2(SrpClient *thiz, uint8_t *M2, size_t *M2_len)
{
    TinyRet ret = TINY_RET_OK;

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(M2, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(M2_len, TINY_RET_E_ARG_NULL);

    // M2 = H(A | M1 | K)

    do
    {
        uint8_t A[A_LEN];
        uint8_t M1[M1_LEN];
        uint8_t K[K_LEN];

        if (0 != mpi_write_binary(&thiz->A, A, A_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != mpi_write_binary(&thiz->M1, M1, M1_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != mpi_write_binary(&thiz->K, K, K_LEN))
        {
            LOG_D(TAG, "mpi_write_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        ret = srp_compute_M2(A, M1, K, M2);
        if (RET_FAILED(ret))
        {
            LOG_D(TAG, "srp_compute_M2 FAILED.");
            break;
        }

        if (0 != mpi_read_binary(&thiz->M2, M2, M2_LEN))
        {
            LOG_D(TAG, "mpi_read_binary FAILED.");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (*M2_len < M1_LEN)
        {
            LOG_D(TAG, "len is too short");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        *M2_len = M1_LEN;
    } while (false);

    return ret;
}