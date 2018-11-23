#ifndef    __ed25519_h__
#define    __ed25519_h__

#include <tiny_base.h>


TINY_BEGIN_DECLS


#define ED25519_PUBLIC_KEY_BYTES        32
#define ED25519_SECRET_KEY_BYTES        32
#define ED25519_SIGNATURE_BYTES            64

void ed25519_make_key_pair(uint8_t *pk, uint8_t *sk);

void ed25519_sign(uint8_t *signature, const void *data, size_t length, const uint8_t *pk, const uint8_t *sk);

int ed25519_verify(const void *data, size_t length, const uint8_t *signature, const uint8_t *pk);


TINY_END_DECLS

#endif // __ed25519_h__
