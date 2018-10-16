#-----------------------------------------------------------------------------
#
# TinyCrypt
#
#-----------------------------------------------------------------------------


#-----------------------
# Base64
#-----------------------
SET(Base64_Header
        base64/tiny_base64.h
        )

SET(Base64_Source
        base64/tiny_base64.c
        )

SOURCE_GROUP(Base64\\headers FILES ${Base64_Header})
SOURCE_GROUP(Base64\\Source FILES ${Base64_Source})

#-----------------------
# bignum
#-----------------------
SET(Bignum_Header
        bignum/polarssl/bignum.h
        bignum/polarssl/bn_mul.h
        bignum/polarssl/polarssl_check_config.h
        bignum/polarssl/polarssl_config.h
        bignum/polarssl/polarssl_platform.h
        )

SET(Bignum_Source
        bignum/polarssl/bignum.c
        bignum/polarssl/polarssl_platform.c
        )

SOURCE_GROUP(Bignum\\headers FILES ${Bignum_Header})
SOURCE_GROUP(Bignum\\Source FILES ${Bignum_Source})

#-----------------------
# srp
#-----------------------

IF (SRP_REMOTE_ENABLED EQUAL 1)
    MESSAGE(STATUS "SRP Type: remote")

    SET(Srp_Header
            srp/SrpServer.h
            srp/srp_define.h
            )

    SET(Srp_Source
            srp/remote/SrpServer.c
            )

ELSE ()
    MESSAGE(STATUS "SRP Type: local")

    SET(Srp_Header
            srp/SrpServer.h
            srp/srp_define.h
            srp/local/srp_both.h
            srp/local/srp_NG3072.h
            )

    SET(Srp_Source
            srp/local/SrpServer.c
            srp/local/srp_both.c
            srp/local/srp_NG3072.c
            )
ENDIF ()

SOURCE_GROUP(Srp\\headers FILES ${Srp_Header})
SOURCE_GROUP(Srp\\Source FILES ${Srp_Source})

#-----------------------
# sha
#-----------------------
SET(SHA_Header
        sha/sha1.h
        sha/sha512.h
        )

SET(SHA_Source
        sha/sha1.c
        sha/sha512.c
        )

SOURCE_GROUP(SHA\\headers FILES ${SHA_Header})
SOURCE_GROUP(SHA\\Source FILES ${SHA_Source})

#-----------------------
# hmac
#-----------------------
SET(Hmac_Header
        hmac/hmac.h
        )

SET(Hmac_Source
        hmac/hmac.c
        )

#-----------------------
# hkdf
#-----------------------
SET(Hkdf_Header
        hkdf/HKDF.h
        )

SET(Hkdf_Source
        hkdf/HKDF.c
        )

SOURCE_GROUP(HKDF\\headers FILES ${Hkdf_Header})
SOURCE_GROUP(HKDF\\Source FILES ${Hkdf_Source})

#-----------------------
# Chacha20
#-----------------------
SET(Chacha20_Header
        chacha20/ChaCha20.h
        )

SET(Chacha20_Source
        chacha20/ChaCha20.c
        )

SOURCE_GROUP(Chacha20\\headers FILES ${Chacha20_Header})
SOURCE_GROUP(Chacha20\\Source FILES ${Chacha20_Source})

#-----------------------
# Poly1305
#-----------------------
SET(Poly1305_Header
        poly1305/Poly1305.h
        )

SET(Poly1305_Source
        poly1305/Poly1305.c
        )

SOURCE_GROUP(Poly1305\\headers FILES ${Poly1305_Header})
SOURCE_GROUP(Poly1305\\Source FILES ${Poly1305_Source})

#-----------------------
# Chacha20poly1305
#-----------------------
SET(Chacha20poly1305_Header
        chacha20poly1305/tiny_chacha20poly1305.h
        )

SET(Chacha20poly1305_Source
        chacha20poly1305/tiny_chacha20poly1305.c
        )

SOURCE_GROUP(Chacha20poly1305\\headers FILES ${Chacha20poly1305_Header})
SOURCE_GROUP(Chacha20poly1305\\Source FILES ${Chacha20poly1305_Source})

#-----------------------
# x25519
#-----------------------
SET(x25519_Header
        x25519/tiny_ed25519.h
        x25519/tiny_curve25519.h
        x25519/ed25519_key_exchange.h
        x25519/precomp_data.h
        x25519/fe.h
        x25519/ge.h
        x25519/sc.h
        x25519/crypt25519.h
        )

SET(x25519_Source
        x25519/tiny_ed25519.c
        x25519/tiny_curve25519.c
        x25519/ed25519_key_exchange.c
        x25519/fe.c
        x25519/ge.c
        x25519/sc.c
        x25519/crypt25519.c
        )

SOURCE_GROUP(X25519\\headers FILES ${x25519_Header})
SOURCE_GROUP(X25519\\Source FILES ${x25519_Source})

#-----------------------
# common
#-----------------------
SET(Common_Header
        common/tiny_crypto_api.h
        )

SOURCE_GROUP(Common\\headers FILES ${Common_Header})

#----------------------------------------------------------------------------
# source
#----------------------------------------------------------------------------
SET(SRC
        commcon/tiny_crypto_api.h
        ${Common_Header}
        ${Base64_Header}
        ${Base64_source}
        ${Bignum_Header}
        ${Bignum_Source}
        ${Srp_Header}
        ${Srp_Source}
        ${SHA_Header}
        ${SHA_Source}
        ${Hmac_Header}
        ${Hmac_Source}
        ${Hkdf_Header}
        ${Hkdf_Source}
        ${Chacha20_Header}
        ${Chacha20_Source}
        ${Poly1305_Header}
        ${Poly1305_Source}
        ${Chacha20poly1305_Header}
        ${Chacha20poly1305_Source}
        ${x25519_Header}
        ${x25519_Source}
        )

#----------------------------------------------------------------------------
# static library
#----------------------------------------------------------------------------
ADD_LIBRARY(tiny_crypto_static STATIC ${SRC})
SET_TARGET_PROPERTIES(tiny_crypto_static PROPERTIES OUTPUT_NAME "tiny_crypto_static")
SET_TARGET_PROPERTIES(tiny_crypto_static PROPERTIES LINKER_LANGUAGE C)

#----------------------------------------------------------------------------
# shared library
#----------------------------------------------------------------------------
#ADD_LIBRARY(iot_crypto_shared SHARED ${SRC})
#SET_TARGET_PROPERTIES(iot_crypto_shared PROPERTIES OUTPUT_NAME "iot_crypto")
#SET_TARGET_PROPERTIES(iot_crypto_shared PROPERTIES LINKER_LANGUAGE C)
#TARGET_LINK_LIBRARIES(iot_crypto_shared ${OS_LIB} tiny_shared)

#-----------------------------------------------------------------------------
#
# generator
#
#-----------------------------------------------------------------------------
ADD_SUBDIRECTORY(ed25519_generator)
ADD_SUBDIRECTORY(srp_generator)

#-----------------------------------------------------------------------------
#
# test
#
#-----------------------------------------------------------------------------
#ADD_SUBDIRECTORY(srp_test)
