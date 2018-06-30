#include <srp/SrpServer.h>

void tiny_print_mem(const char *tag, const char *function)
{
}

void tiny_sleep(int ms)
{
}

static void print_binary(const char *tag, const uint8_t *value, uint32_t length)
{
    printf("static uint8_t %s[%d] = {", tag, length);

    for (uint32_t i = 0; i < length; ++i)
    {
        printf("0x%02x", value[i]);

        if (i < length - 1)
        {
            printf(", ");
        }

        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
    printf("};\n");
}

#define I   "Pair-Setup"
#define P   "031-45-154"

int main(void)
{
#if 0
    SrpServer server;

    if (RET_FAILED(SrpServer_Construct(&server, I, P)))
    {
        return 0;
    }

    if (RET_FAILED(SrpServer_Initialize_svbB(&server)))
    {
        return 0;
    }

    print_binary("s", server.s, salt_LEN);
    print_binary("v", server.v, v_LEN);
    print_binary("b", server.b, b_LEN);
    print_binary("B", server.B, B_LEN);
#endif

    return 0;
}