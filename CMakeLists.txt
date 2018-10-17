CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(TinyCrypto C)

SET(PROJ_NAME "TinyCrypto")

#---------------------------------------------------------------------------------------
#
# include dir
#
#---------------------------------------------------------------------------------------
SET(SOURCE_ROOT ${PROJECT_SOURCE_DIR}/source/src)
INCLUDE_DIRECTORIES(${SOURCE_ROOT})

SET(TINY_ROOT ${PROJECT_SOURCE_DIR}/../tiny)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyBase)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyPortable)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyPorting)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyContainer)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyLog)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyStringUtil)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyRandom)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyBuffer)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/StringArray)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/Netty)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/HttpClient)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/Json)

#---------------------------------------------------------------------------------------
#
# link dir
#
#---------------------------------------------------------------------------------------
LINK_DIRECTORIES(${TINY_ROOT}/target)

#-------------------------------------------------------------------------------------
# output dir
#-------------------------------------------------------------------------------------
SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/target)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/target)
MESSAGE(STATUS "executable output:  ${EXECUTABLE_OUTPUT_PATH}")
MESSAGE(STATUS "library output: ${LIBRARY_OUTPUT_PATH}")

#-------------------------------------------------------------------------------------
#
# Source
#
#-------------------------------------------------------------------------------------
SET(TinyCrypto_Header
        ${SOURCE_ROOT}/common/tiny_crypto_api.h
        ${SOURCE_ROOT}/base64/tiny_base64.h
        ${SOURCE_ROOT}/bignum/polarssl/bignum.h
        ${SOURCE_ROOT}/bignum/polarssl/bn_mul.h
        ${SOURCE_ROOT}/bignum/polarssl/polarssl_check_config.h
        ${SOURCE_ROOT}/bignum/polarssl/polarssl_config.h
        ${SOURCE_ROOT}/bignum/polarssl/polarssl_platform.h
        ${SOURCE_ROOT}/srp/srp_define.h
        ${SOURCE_ROOT}/srp/srp_both.h
        ${SOURCE_ROOT}/srp/srp_NG3072.h
        ${SOURCE_ROOT}/srp/SrpServer.h
        ${SOURCE_ROOT}/srp/SrpClient.h
        ${SOURCE_ROOT}/sha/sha1.h
        ${SOURCE_ROOT}/sha/sha512.h
        ${SOURCE_ROOT}/hmac/hmac.h
        ${SOURCE_ROOT}/hkdf/HKDF.h
        ${SOURCE_ROOT}/chacha20/ChaCha20.h
        ${SOURCE_ROOT}/poly1305/Poly1305.h
        ${SOURCE_ROOT}/chacha20poly1305/tiny_chacha20poly1305.h
        ${SOURCE_ROOT}/x25519/tiny_ed25519.h
        ${SOURCE_ROOT}/x25519/tiny_curve25519.h
        ${SOURCE_ROOT}/x25519/tiny_ed25519_key_exchange.h
        ${SOURCE_ROOT}/x25519/tiny_x25519_key_convert.h
        ${SOURCE_ROOT}/x25519/tiny_x25519_fe.h
        ${SOURCE_ROOT}/x25519/tiny_x25519_ge.h
        ${SOURCE_ROOT}/x25519/tiny_x25519_sc.h
        ${SOURCE_ROOT}/secret/SecretKey.h
        )

SET(TinyCrypto_Source
        ${SOURCE_ROOT}/base64/tiny_base64.c
        ${SOURCE_ROOT}/bignum/polarssl/bignum.c
        ${SOURCE_ROOT}/bignum/polarssl/polarssl_platform.c
        ${SOURCE_ROOT}/srp/srp_both.c
        ${SOURCE_ROOT}/srp/srp_NG3072.c
        ${SOURCE_ROOT}/srp/SrpServer.c
        ${SOURCE_ROOT}/srp/SrpClient.c
        ${SOURCE_ROOT}/sha/sha1.c
        ${SOURCE_ROOT}/sha/sha512.c
        ${SOURCE_ROOT}/hmac/hmac.c
        ${SOURCE_ROOT}/hkdf/HKDF.c
        ${SOURCE_ROOT}/chacha20/ChaCha20.c
        ${SOURCE_ROOT}/poly1305/Poly1305.c
        ${SOURCE_ROOT}/chacha20poly1305/tiny_chacha20poly1305.c
        ${SOURCE_ROOT}/x25519/tiny_ed25519.c
        ${SOURCE_ROOT}/x25519/tiny_curve25519.c
        ${SOURCE_ROOT}/x25519/tiny_ed25519_key_exchange.c
        ${SOURCE_ROOT}/x25519/tiny_x25519_key_convert.c
        ${SOURCE_ROOT}/x25519/tiny_x25519_fe.c
        ${SOURCE_ROOT}/x25519/tiny_x25519_ge.c
        ${SOURCE_ROOT}/x25519/tiny_x25519_sc.c
        )

SOURCE_GROUP(TinyCrypto\\headers FILES ${TinyCrypto_Header})
SOURCE_GROUP(TinyCrypto\\sources FILES ${TinyCrypto_Source})

SET(SRC
        ${TinyCrypto_Header}
        ${TinyCrypto_Source}
    )

#----------------------------------------------------------------------------
# static library
#----------------------------------------------------------------------------
IF (EXPORT_STATIC_LIBRARY EQUAL 1)
ADD_LIBRARY(tinycrypto_static STATIC ${SRC})
SET_TARGET_PROPERTIES(tinycrypto_static PROPERTIES OUTPUT_NAME "tinycrypto_static")
SET_TARGET_PROPERTIES(tinycrypto_static PROPERTIES LINKER_LANGUAGE C)
ENDIF ()

#----------------------------------------------------------------------------
# shared library
#----------------------------------------------------------------------------
IF (EXPORT_SHARED_LIBRARY EQUAL 1)
MESSAGE(STATUS "link library: ${DEPENDENCE_LIB}")
ADD_LIBRARY(tinycrypto SHARED ${SRC})
SET_TARGET_PROPERTIES(tinycrypto PROPERTIES OUTPUT_NAME "tinycrypto")
SET_TARGET_PROPERTIES(tinycrypto PROPERTIES LINKER_LANGUAGE C)
TARGET_LINK_LIBRARIES(tinycrypto ${DEPENDENCE_LIB})
ENDIF ()
