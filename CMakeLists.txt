CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(TinyCrypto C)

SET(PROJ_NAME "TinyCrypto")

#---------------------------------------------------------------------------------------
#
# include dir
#
#---------------------------------------------------------------------------------------
SET(SOURCE_ROOT ${PROJECT_SOURCE_DIR}/source/src)
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
IF (SRP_REMOTE_ENABLED EQUAL 1)
    SET(HapCrypto_Header
        ${SOURCE_ROOT}/common/crypto_api.h
        ${SOURCE_ROOT}/bignum/polarssl/bignum.h
        ${SOURCE_ROOT}/gbignum/polarssl/bn_mul.h
        ${SOURCE_ROOT}/gbignum/polarssl/polarssl_check_config.h
        ${SOURCE_ROOT}/gbignum/polarssl/polarssl_config.h
        ${SOURCE_ROOT}/gbignum/polarssl/polarssl_platform.h
        ${SOURCE_ROOT}/gsrp/srp_define.h
        ${SOURCE_ROOT}/gsrp/SrpServer.h
        ${SOURCE_ROOT}/gsha/sha512.h
        ${SOURCE_ROOT}/ghmac/hmac.h
        ${SOURCE_ROOT}/ghkdf/HKDF.h
        ${SOURCE_ROOT}/gchacha20/ChaCha20.h
        ${SOURCE_ROOT}/gpoly1305/Poly1305.h
        ${SOURCE_ROOT}/gchacha20poly1305/chacha20poly1305.h
        ${SOURCE_ROOT}/gcrypt25519/crypt25519.h
        ${SOURCE_ROOT}/ged25519/Ed25519.h
        ${SOURCE_ROOT}/gcurve25519/Curve25519.h
        )

    SET(HapCrypto_Source
        ${SOURCE_ROOT}/gbignum/polarssl/bignum.c
        ${SOURCE_ROOT}/gbignum/polarssl/polarssl_platform.c
        ${SOURCE_ROOT}/gsrp/remote/SrpServer.c
        ${SOURCE_ROOT}/gsha/sha512.c
        ${SOURCE_ROOT}/ghmac/hmac.c
        ${SOURCE_ROOT}/ghkdf/HKDF.c
        ${SOURCE_ROOT}/gchacha20/ChaCha20.c
        ${SOURCE_ROOT}/gpoly1305/Poly1305.c
        ${SOURCE_ROOT}/gchacha20poly1305/chacha20poly1305.c
        ${SOURCE_ROOT}/gcrypt25519/crypt25519.c
        ${SOURCE_ROOT}/ged25519/Ed25519.c
        ${SOURCE_ROOT}/gcurve25519/Curve25519.c
        )

ELSE ()
    SET(HapCrypto_Header
        ${SOURCE_ROOT}/gcommon/crypto_api.h
        ${SOURCE_ROOT}/gbignum/polarssl/bignum.h
        ${SOURCE_ROOT}/gbignum/polarssl/bn_mul.h
        ${SOURCE_ROOT}/gbignum/polarssl/polarssl_check_config.h
        ${SOURCE_ROOT}/gbignum/polarssl/polarssl_config.h
        ${SOURCE_ROOT}/gbignum/polarssl/polarssl_platform.h
        ${SOURCE_ROOT}/gsrp/srp_define.h
        ${SOURCE_ROOT}/gsrp/SrpServer.h
        ${SOURCE_ROOT}/gsrp/local/srp_NG3072.h
        ${SOURCE_ROOT}/gsrp/local/srp_both.h
        ${SOURCE_ROOT}/gsha/sha512.h
        ${SOURCE_ROOT}/ghmac/hmac.h
        ${SOURCE_ROOT}/ghkdf/HKDF.h
        ${SOURCE_ROOT}/gchacha20/ChaCha20.h
        ${SOURCE_ROOT}/gpoly1305/Poly1305.h
        ${SOURCE_ROOT}/gchacha20poly1305/chacha20poly1305.h
        ${SOURCE_ROOT}/gcrypt25519/crypt25519.h
        ${SOURCE_ROOT}/ged25519/Ed25519.h
        ${SOURCE_ROOT}/gcurve25519/Curve25519.h
        )

    SET(HapCrypto_Source
        ${SOURCE_ROOT}/gbignum/polarssl/bignum.c
        ${SOURCE_ROOT}/gbignum/polarssl/polarssl_platform.c
        ${SOURCE_ROOT}/gsrp/local/SrpServer.c
        ${SOURCE_ROOT}/gsrp/local/srp_NG3072.c
        ${SOURCE_ROOT}/gsrp/local/srp_both.c
        ${SOURCE_ROOT}/gsha/sha512.c
        ${SOURCE_ROOT}/ghmac/hmac.c
        ${SOURCE_ROOT}/ghkdf/HKDF.c
        ${SOURCE_ROOT}/gchacha20/ChaCha20.c
        ${SOURCE_ROOT}/gpoly1305/Poly1305.c
        ${SOURCE_ROOT}/gchacha20poly1305/chacha20poly1305.c
        ${SOURCE_ROOT}/gcrypt25519/crypt25519.c
        ${SOURCE_ROOT}/ged25519/Ed25519.c
        ${SOURCE_ROOT}/gcurve25519/Curve25519.c
        )
ENDIF ()

SOURCE_GROUP(HapCrypto\\headers FILES ${TinyCrypto_Header})
SOURCE_GROUP(HapCrypto\\sources FILES ${TinyCrypto_Source})

SET(SRC
        ${TinyCrypto_Header}
        ${TinyCrypto_Source}
    )

#----------------------------------------------------------------------------
# static library
#----------------------------------------------------------------------------
ADD_LIBRARY(tinycrypto_static STATIC ${SRC})
SET_TARGET_PROPERTIES(tinycrypto_static PROPERTIES OUTPUT_NAME "tinycrypto_static")
SET_TARGET_PROPERTIES(tinycrypto_static PROPERTIES LINKER_LANGUAGE C)

#----------------------------------------------------------------------------
# shared library
#----------------------------------------------------------------------------
MESSAGE(STATUS "link library: ${DEPENDENCE_LIB}")
ADD_LIBRARY(tinycrypto SHARED ${SRC})
SET_TARGET_PROPERTIES(tinycrypto PROPERTIES OUTPUT_NAME "tinycrypto")
SET_TARGET_PROPERTIES(tinycrypto PROPERTIES LINKER_LANGUAGE C)
TARGET_LINK_LIBRARIES(tinycrypto ${DEPENDENCE_LIB})
