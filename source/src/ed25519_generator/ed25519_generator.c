#include <ed25519/Ed25519.h>

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
    }
    printf("};\n");
}

int main(void)
{
    Ed25519KeyPair pair;

    memset(&pair, 0, sizeof(Ed25519KeyPair));
    Ed25519_GenerateKeyPair(&pair);

    print_binary("PrivateKey", pair.privateKey.value, ED25519_PRIVATE_KEY_LENGTH);
    print_binary("PublicKey", pair.publicKey.value, ED25519_PUBLIC_KEY_LENGTH);

    return 0;
}