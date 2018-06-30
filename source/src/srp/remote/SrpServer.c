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
#include <srp/SrpServer.h>
#include <HttpClient.h>
#include <tiny_snprintf.h>
#include <JsonObject.h>
#include <bignum/tiny_bignum.h>
#include <value/JsonString.h>

#define TAG                 "SrpServer"

#define API_TIMEOUT         60
#define API_INITIALIZE      "/crypto/srp/server/instance/initialize"
#define API_VERIFY          "/crypto/srp/server/instance/verify"

#if 1
#define SERVER_IP           "47.93.60.147"
#define SERVER_PORT         8080
#else
#define SERVER_IP           "127.0.0.1"
#define SERVER_PORT         9000
#endif

struct _SrpServer
{
    char            id[18];
    char            username[USERNAME_LEN];
    char            password[PASSWORD_LEN];
    uint8_t         s[salt_LEN];
    uint8_t         B[B_LEN];
    uint8_t         M2[M2_LEN];
    uint8_t         K[K_LEN];
};

TINY_LOR
static TinyRet SrpServer_Construct(SrpServer *thiz, const char *username, const char *password)
{
    TinyRet ret = TINY_RET_OK;
    uint8_t v[6];

    RETURN_VAL_IF_FAIL(thiz, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(username, TINY_RET_E_ARG_NULL);
    RETURN_VAL_IF_FAIL(password, TINY_RET_E_ARG_NULL);

    memset(thiz, 0, sizeof(SrpServer));
    strncpy(thiz->username, username, USERNAME_LEN);
    strncpy(thiz->password, password, USERNAME_LEN);

    tiny_random_create(v, 6);
    memset(thiz->id, 0, 18);
    tiny_snprintf(thiz->id, 18, "%02x:%02x:%02x:%02x:%02x:%02x", v[0], v[1], v[2], v[3], v[4], v[5]);

    return ret;
}

TINY_LOR
static void SrpServer_Dispose(SrpServer *thiz)
{
    RETURN_IF_FAIL(thiz);
    memset(thiz, 0, sizeof(SrpServer));
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
            LOG_E(TAG, "tiny_malloc FAILED.");
            break;
        }

        if (RET_FAILED(SrpServer_Construct(thiz, username, password)))
        {
            LOG_E(TAG, "SrpServer_Construct FAILED.");
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
    HttpClient * client = NULL;
    HttpExchange * exchange = NULL;
    JsonObject * object = NULL;
    tiny_mpi ss;
    tiny_mpi BB;

    tiny_mpi_init(&ss);
    tiny_mpi_init(&BB);

    do
    {
        JsonString *s = NULL;
        JsonString *B = NULL;

        client = HttpClient_New();
        if (client == NULL)
        {
            LOG_E(TAG, "HttpClient_New failed!");
            ret = TINY_RET_E_NEW;
            break;
        }

        object = JsonObject_New();
        if (object == NULL)
        {
            LOG_E(TAG, "JsonObject_New failed!");
            ret = TINY_RET_E_NEW;
            break;
        }

        if (RET_FAILED(JsonObject_PutString(object, "deviceId", thiz->id))
            || RET_FAILED(JsonObject_PutString(object, "username", thiz->username))
            || RET_FAILED(JsonObject_PutString(object, "password", thiz->password)))
        {
            LOG_E(TAG, "JsonObject_PutString failed!");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (RET_FAILED(JsonObject_Encode(object, true)))
        {
            LOG_E(TAG, "JsonObject_Encode failed!");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        exchange = HttpExchange_New(SERVER_IP, SERVER_PORT, "POST", API_INITIALIZE, API_TIMEOUT, (uint8_t *)object->string, object->size);
        if (exchange == NULL)
        {
            LOG_E(TAG, "HttpExchange_New failed!");
            ret = TINY_RET_E_NEW;
            break;
        }

        if (RET_FAILED(HttpHeader_Set(&exchange->request, "Content-Type", "application/json")))
        {
            LOG_E(TAG, "HttpHeader_Set failed!");
            ret = TINY_RET_E_NEW;
            break;
        }

        LOG_I(TAG, "POST: %s", API_INITIALIZE);

        ret = HttpClient_Send(client, exchange);
        if (RET_FAILED(ret))
        {
            LOG_E(TAG, "HttpClient_Send failed!");
            break;
        }

        LOG_I(TAG, "HTTP/1.1 %d", exchange->status);

        if (exchange->status != HTTP_STATUS_OK)
        {
            LOG_E(TAG, "exchange->status: %d", exchange->status);
            ret = TINY_RET_E_ARG_INVALID;
            break;
        }

        JsonObject_Delete(object);

        object = JsonObject_NewString(exchange->content);
        if (object == NULL)
        {
            LOG_E(TAG, "JsonObject_NewString failed!");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        s = JsonObject_GetString(object, "s");
        B = JsonObject_GetString(object, "B");

        if (s == NULL || B == NULL)
        {
            LOG_E(TAG, "s or B is NULL");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        LOG_D(TAG, "s: %s", s->value);
        LOG_D(TAG, "B: %s", B->value);

        if (0 != mpi_read_string(&ss, 16, s->value))
        {
            LOG_E(TAG, "mpi_read_string FAILED.");
            ret =  TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != mpi_read_string(&BB, 16, B->value))
        {
            LOG_E(TAG, "mpi_read_string FAILED.");
            ret =  TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != tiny_mpi_write_binary(&ss, thiz->s, salt_LEN))
        {
            LOG_E(TAG, "mpi_write_binary FAILED.");
            ret =  TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != tiny_mpi_write_binary(&BB, thiz->B, B_LEN))
        {
            LOG_E(TAG, "mpi_write_binary FAILED.");
            ret =  TINY_RET_E_INTERNAL;
            break;
        }
    } while (false);

    if (object != NULL)
    {
        JsonObject_Delete(object);
    }

    if (exchange != NULL)
    {
        HttpExchange_Delete(exchange);
    }

    if (client != NULL)
    {
        HttpClient_Delete(client);
    }

    tiny_mpi_free(&ss);
    tiny_mpi_free(&BB);

    return ret;
}

TINY_LOR
TinyRet SrpServer_Set_svbB(SrpServer *thiz, uint8_t s[salt_LEN], uint8_t v[v_LEN], uint8_t b[b_LEN], uint8_t B[B_LEN])
{
    return TINY_RET_E_NOT_IMPLEMENTED;
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
TinyRet SrpServer_Verify(SrpServer *thiz, const uint8_t *A, uint32_t len, const uint8_t *M1, uint32_t size)
{
    TinyRet ret = TINY_RET_OK;
    HttpClient * client = NULL;
    HttpExchange * exchange = NULL;
    JsonObject * object = NULL;
    tiny_mpi AA;
    tiny_mpi MM1;
    tiny_mpi KK;
    tiny_mpi MM2;

    tiny_mpi_init(&AA);
    tiny_mpi_init(&MM1);
    tiny_mpi_init(&KK);
    tiny_mpi_init(&MM2);

    do
    {
        char _A[1024];
        char _M1[150];
        size_t _A_LEN = 1024;
        size_t _M1_LEN = 150;
        JsonString *K = NULL;
        JsonString *M2 = NULL;

        client = HttpClient_New();
        if (client == NULL)
        {
            LOG_E(TAG, "HttpClient_New failed!");
            ret = TINY_RET_E_NEW;
            break;
        }

        if (0 != mpi_read_binary(&AA, A, len))
        {
            LOG_D(TAG, "mpi_read_binary FAILED.");
            ret =  TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != mpi_read_binary(&MM1, M1, size))
        {
            LOG_D(TAG, "mpi_read_binary FAILED.");
            ret =  TINY_RET_E_INTERNAL;
            break;
        }

        memset(_A, 0, _A_LEN);
        memset(_M1, 0, _M1_LEN);

        if (0 != tiny_mpi_write_string(&AA, 16, _A, &_A_LEN))
        {
            LOG_E(TAG, "tiny_mpi_write_string FAILED: A");
            ret =  TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != tiny_mpi_write_string(&MM1, 16, _M1, &_M1_LEN))
        {
            LOG_E(TAG, "tiny_mpi_write_string FAILED: M1");
            ret =  TINY_RET_E_INTERNAL;
            break;
        }

        printf("AA: %d\n", (int) _A_LEN);
        printf("M1: %d\n", (int) _M1_LEN);

        object = JsonObject_New();
        if (object == NULL)
        {
            LOG_E(TAG, "JsonObject_New failed!");
            ret = TINY_RET_E_NEW;
            break;
        }

        if (RET_FAILED(JsonObject_PutString(object, "deviceId", thiz->id))
            || RET_FAILED(JsonObject_PutString(object, "A", _A))
            || RET_FAILED(JsonObject_PutString(object, "M1", _M1)))
        {
            LOG_E(TAG, "JsonObject_PutString failed!");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (RET_FAILED(JsonObject_Encode(object, true)))
        {
            LOG_E(TAG, "JsonObject_Encode failed!");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        exchange = HttpExchange_New(SERVER_IP, SERVER_PORT, "POST", API_VERIFY, API_TIMEOUT, (uint8_t *)object->string, object->size);
        if (exchange == NULL)
        {
            LOG_E(TAG, "HttpExchange_New failed!");
            ret = TINY_RET_E_NEW;
            break;
        }

        if (RET_FAILED(HttpHeader_Set(&exchange->request, "Content-Type", "application/json")))
        {
            LOG_E(TAG, "HttpHeader_Set failed!");
            ret = TINY_RET_E_NEW;
            break;
        }

        LOG_I(TAG, "POST: /crypto/srp/server/instance/verify");

        ret = HttpClient_Send(client, exchange);
        if (RET_FAILED(ret))
        {
            LOG_E(TAG, "HttpClient_Send failed!");
            break;
        }

        LOG_I(TAG, "HTTP/1.1 %d", exchange->status);

        if (exchange->status != HTTP_STATUS_OK)
        {
            LOG_E(TAG, "exchange->status: %d", exchange->status);
            ret = TINY_RET_E_ARG_INVALID;
            break;
        }

        JsonObject_Delete(object);
        object = JsonObject_NewString(exchange->content);
        if (object == NULL)
        {
            LOG_E(TAG, "JsonObject_NewString failed!");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        K = JsonObject_GetString(object, "K");
        M2 = JsonObject_GetString(object, "M2");

        if (K == NULL || M2 == NULL)
        {
            LOG_E(TAG, "K or M2 is NULL");
            ret = TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != mpi_read_string(&KK, 16, K->value))
        {
            LOG_E(TAG, "mpi_read_string FAILED: K");
            ret =  TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != mpi_read_string(&MM2, 16, M2->value))
        {
            LOG_E(TAG, "mpi_read_string FAILED: M2");
            ret =  TINY_RET_E_INTERNAL;
            break;
        }

        LOG_D(TAG, "K: %s", K->value);
        LOG_D(TAG, "M2: %s", M2->value);

        if (0 != tiny_mpi_write_binary(&KK, thiz->K, K_LEN))
        {
            LOG_E(TAG, "mpi_write_binary FAILED: K");
            ret =  TINY_RET_E_INTERNAL;
            break;
        }

        if (0 != tiny_mpi_write_binary(&MM2, thiz->M2, M2_LEN))
        {
            LOG_E(TAG, "mpi_write_binary FAILED: M2");
            ret =  TINY_RET_E_INTERNAL;
            break;
        }
    } while (false);

    if (object != NULL)
    {
        JsonObject_Delete(object);
    }

    if (exchange != NULL)
    {
        HttpExchange_Delete(exchange);
    }

    if (client != NULL)
    {
        HttpClient_Delete(client);
    }

    tiny_mpi_free(&AA);
    tiny_mpi_free(&MM1);
    tiny_mpi_free(&KK);
    tiny_mpi_free(&MM2);

    return ret;
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