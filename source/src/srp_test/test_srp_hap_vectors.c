#include "srp/SrpClient.h"
#include "srp/SrpServer.h"
#include "SrpVectors.h"
#include "HapTestVectors.h"
#include "HapVectorsExample1.h"

void tiny_print_mem(const char *tag, const char *function)
{
}

void tiny_sleep(int ms)
{
}

void print_binary(const char *title, const uint8_t data[], size_t len)
{
    printf("[ %s ] = \n", title);
    for (int j = 0; j < len; ++j)
    {
        printf("%02X", data[j]);
        if ((j + 1) % 32 == 0)
        {
            printf("\n");
        }
        else
        {
            if (! ((j + 1) % 4))
            {
                printf(" ");
            }
        }
    }
    printf("\n");
}

bool equals(const char * name, const uint8_t data[], size_t len, const char *hex)
{
    char buf[1024];

    print_binary(name, data, len);

    memset(buf, 0, 1024);

    for (int j = 0; j < len; ++j)
    {
        char value[10];
        memset(value, 0, 10);

        tiny_snprintf(value, 10, "%02X", data[j]);
        strcat(buf, value);
    }

    return STR_EQUAL(buf, hex);
}

static void test_server(SrpVectors * t)
{
    SrpServer *server = NULL;

    server = SrpServer_New(t->I, t->P);
    if (server == NULL)
    {
        printf("SrpServer_New failed\n");
        return;
    }

    if (RET_FAILED(SrpServer_set_s_hex(server, t->s)))
    {
        printf("SrpServer_set_s_hex failed\n");
        return;
    }

    if (RET_FAILED(SrpServer_compute_v(server)))
    {
        printf("SrpServer_compute_v failed\n");
        return;
    }

    if (! equals("v", server->v, v_LEN, t->v))
    {
        printf("v INVALID\n");
        return;
    }

    if (RET_FAILED(SrpServer_set_b_hex(server, t->b)))
    {
        printf("SrpServer_set_b_hex failed\n");
        return;
    }

    if (RET_FAILED(SrpServer_generate_B(server)))
    {
        printf("SrpServer_generate_B failed\n");
        return;
    }

    if (! equals("B", server->B, B_LEN, t->B))
    {
        printf("B INVALID\n");
        return;
    }

    if (RET_FAILED(SrpServer_set_A_hex(server, t->A)))
    {
        printf("SrpServer_set_A_hex failed\n");
        return;
    }

    if (RET_FAILED(SrpServer_compute_u(server)))
    {
        printf("SrpServer_compute_u failed\n");
        return;
    }

    if (! equals("u", server->u, u_LEN, t->u))
    {
        printf("u INVALID\n");
        return;
    }

    if (RET_FAILED(SrpServer_compute_S(server)))
    {
        printf("SrpServer_compute_S failed\n");
        return;
    }

    if (! equals("S", server->S, S_LEN, t->S))
    {
        printf("S INVALID\n");
        return;
    }

    if (RET_FAILED(SrpServer_compute_K(server)))
    {
        printf("SrpServer_compute_K failed\n");
        return;
    }

    if (! equals("K", server->K, K_LEN, t->K))
    {
        printf("S INVALID\n");
        return;
    }

    if (RET_FAILED(SrpServer_compute_M1(server)))
    {
        printf("SrpServer_compute_M1 failed\n");
        return;
    }

    print_binary("M1", server->M1, M1_LEN);

    if (RET_FAILED(SrpServer_compute_M2(server)))
    {
        printf("SrpServer_compute_M2 failed\n");
        return;
    }

    print_binary("M2", server->M2, M2_LEN);

    printf("SrpServer test finished!\n");
}

static void test_client(SrpVectors * t)
{
}

static void test(SrpVectors * t)
{
    printf("test: %s: %s\n", t->I, t->P);

    test_server(t);
    test_client(t);
}

int main()
{
    test(HapTestVectors());
    test(HapVectorsExample1());

    return 0;
}