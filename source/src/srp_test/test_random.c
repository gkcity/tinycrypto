#include "srp/SrpClient.h"
#include "srp/SrpServer.h"

#define S_USERNAME      "alice"
#define S_PASSWORD      "password123"

#define C_USERNAME      "alice"
#define C_PASSWORD      "password123"

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

int main()
{
    SrpServer *server = NULL;
    SrpClient *client = NULL;
    uint8_t s[1024];
    uint8_t B[1024];
    uint8_t A[1024];
    uint8_t server_u[1024];
    uint8_t server_S[1024];
    uint8_t server_K[1024];
    uint8_t server_M1[1024];
    uint8_t server_M2[1024];
    uint8_t client_u[1024];
    uint8_t client_S[1024];
    uint8_t client_K[1024];
    uint8_t client_M1[1024];
    uint8_t client_M2[1024];
    size_t s_len = 1024;
    size_t B_len = 1024;
    size_t A_len = 1024;
    size_t server_u_len = 1024;
    size_t server_S_len = 1024;
    size_t server_K_len = 1024;
    size_t server_M1_len = 1024;
    size_t server_M2_len = 1024;
    size_t client_u_len = 1024;
    size_t client_S_len = 1024;
    size_t client_K_len = 1024;
    size_t client_M1_len = 1024;
    size_t client_M2_len = 1024;

    memset(s, 0, 1024);
    memset(B, 0, 1024);
    memset(A, 0, 1024);
    memset(server_u, 0, 1024);
    memset(server_S, 0, 1024);
    memset(server_K, 0, 1024);
    memset(server_M1, 0, 1024);
    memset(server_M2, 0, 1024);
    memset(client_u, 0, 1024);
    memset(client_S, 0, 1024);
    memset(client_K, 0, 1024);
    memset(client_M1, 0, 1024);
    memset(client_M2, 0, 1024);
    
    server = SrpServer_New(S_USERNAME, S_PASSWORD);
    if (server == NULL)
    {
        printf("SrpServer_New failed\n");
        return 0;
    }

    client = SrpClient_New(C_USERNAME, C_PASSWORD);
    if (client == NULL)
    {
        printf("SrpClient_New failed\n");
        return 0;
    }

    /**
     * STEP 1. Server generate: s & B
     */
    printf("STEP 1. Server generate: s & B\n");

    if (RET_FAILED(SrpServer_generate_s(server, s, &s_len)))
    {
        printf("SrpServer_generate_s failed\n");
        return 0;
    }
    print_binary("s", s, s_len);

    if (RET_FAILED(SrpServer_generate_B(server, B, &B_len)))
    {
        printf("SrpServer_generate_B failed\n");
        return 0;
    }
    print_binary("B", B, B_len);

    /**
     * STEP 2. Server send s & B -> client
     */
    printf("STEP 2. Server send s & B -> client\n");

    /**
     * STEP 3. Client generate A
     */
    printf("STEP 3. Client generate A\n");

    if (RET_FAILED(SrpClient_set_s(client, s, s_len)))
    {
        printf("SrpClient_set_s failed");
        return 0;
    }

    if (RET_FAILED(SrpClient_generate_A(client, A, &A_len)))
    {
        printf("SrpClient_generate_A failed\n");
        return 0;
    }
    print_binary("A", A, A_len);

    /**
     * STEP 4. Client send A -> Server
     */
    printf("STEP 4. Client send A -> Server\n");

    /**
     * STEP 5. Server compute u(Random Scrambling Parameter) & S(Premaster Secret) & K(Session Key)
     */
    printf("STEP 5. Server compute u(Random Scrambling Parameter) & S(Premaster Secret) & K(Session Key)\n");

    if (RET_FAILED(SrpServer_set_A(server, A, A_len)))
    {
        printf("SrpServer_set_A failed\n");
        return 0;
    }
    if (RET_FAILED(SrpServer_compute_u(server, server_u, &server_u_len)))
    {
        printf("SrpServer_compute_u failed\n");
        return 0;
    }
    print_binary("server u", server_u, server_u_len);

    if (RET_FAILED(SrpServer_compute_S(server, server_S, &server_S_len)))
    {
        printf("SrpServer_compute_u failed\n");
        return 0;
    }
    print_binary("server S", server_S, server_S_len);

    if (RET_FAILED(SrpServer_compute_K(server, server_K, &server_K_len)))
    {
        printf("SrpServer_compute_K failed\n");
        return 0;
    }
    print_binary("server K", server_K, server_K_len);

    /**
     * STEP 6. client compute u(Random Scrambling Parameter) & S(Premaster Secret) & K(Session Key)
     */
    printf("STEP 6. client compute u(Random Scrambling Parameter) & S(Premaster Secret) & K(Session Key)\n");

    if (RET_FAILED(SrpClient_compute_u(client, B, B_len, client_u, &client_u_len)))
    {
        printf("SrpClient_compute_u failed\n");
        return 0;
    }
    print_binary("client u", client_u, client_u_len);

    if (RET_FAILED(SrpClient_compute_S(client, client_S, &client_S_len)))
    {
        printf("SrpClient_compute_S failed\n");
        return 0;
    }
    print_binary("client S", client_S, client_S_len);

    if (RET_FAILED(SrpClient_compute_K(client, client_K, &client_K_len)))
    {
        printf("SrpClient_compute_K failed\n");
        return 0;
    }
    print_binary("client K", client_K, client_K_len);

    /**
     * STEP 7. compute m1 & m2
    */
    printf("STEP 7. compute m1 & m2\n");
    if (RET_FAILED(SrpServer_compute_M1(server, server_M1, &server_M1_len)))
    {
        printf("SrpServer_compute_M1 failed\n");
        return 0;
    }
    print_binary("server M1", server_M1, server_M1_len);

    if (RET_FAILED(SrpClient_compute_M1(client, client_M1, &client_M1_len)))
    {
        printf("SrpClient_compute_M1 failed\n");
        return 0;
    }
    print_binary("client M1", client_M1, client_M1_len);

    if (RET_FAILED(SrpServer_compute_M2(server, server_M2, &server_M2_len)))
    {
        printf("SrpServer_compute_M2 failed\n");
        return 0;
    }
    print_binary("server M2", server_M2, server_M2_len);

    if (RET_FAILED(SrpClient_compute_M2(client, client_M2, &client_M2_len)))
    {
        printf("SrpClient_compute_M2 failed\n");
        return 0;
    }
    print_binary("client M2", client_M2, client_M2_len);

    /**
     * STEP 8. check u & S & K
     */
    printf("STEP 8. check u & S & K\n");

    if (strcmp(client_u, server_u) == 0) {
        printf("    u is equal!\n");
    }
    else {
        printf("    u is not equal!\n");
    }

    if (strcmp(client_S, server_S) == 0) {
        printf("    S is equal!\n");
    }
    else {
        printf("    S is not equal!\n");
    }

    if (strcmp(client_K, server_K) == 0) {
        printf("    K is equal!\n");
    }
    else {
        printf("    K is not equal!\n");
    }

    if (strcmp(client_M1, server_M1) == 0) {
        printf("    M1 is equal!\n");
    }
    else {
        printf("    M1 is not equal!\n");
    }

    if (strcmp(client_M2, server_M2) == 0) {
        printf("    M2 is equal!\n");
    }
    else {
        printf("    M2 is not equal!\n");
    }

    return 0;
}