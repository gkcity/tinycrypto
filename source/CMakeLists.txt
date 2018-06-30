CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(TinyHAP-DEBUG C)

SET(PROJ_NAME "TinyHAP-DEBUG")

#---------------------------------------------------------------------------------------
#
# include dir
#
#---------------------------------------------------------------------------------------
SET(SOURCE_ROOT ${PROJECT_SOURCE_DIR}/src)
SET(TINY_ROOT ${PROJECT_SOURCE_DIR}/../../tiny)
SET(TINYFX_ROOT ${PROJECT_SOURCE_DIR}/../../tinyfx)
SET(TINYMDNS_ROOT ${PROJECT_SOURCE_DIR}/../../tinymdns)

INCLUDE_DIRECTORIES(${SOURCE_ROOT}/HapCrypto)
INCLUDE_DIRECTORIES(${SOURCE_ROOT}/HapSupport)
INCLUDE_DIRECTORIES(${SOURCE_ROOT}/HapOnLocal)
INCLUDE_DIRECTORIES(${SOURCE_ROOT}/HapOnCloud)

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

INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyUmm)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyMd5)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyThread)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyUuid)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyWorker)

INCLUDE_DIRECTORIES(${TINYFX_ROOT}/source/src/IotDeviceManager)
INCLUDE_DIRECTORIES(${TINYFX_ROOT}/source/src/IotTypedef)
INCLUDE_DIRECTORIES(${TINYFX_ROOT}/source/src/IotOperation)
INCLUDE_DIRECTORIES(${TINYFX_ROOT}/source/src/IotInstance)
INCLUDE_DIRECTORIES(${TINYMDNS_ROOT}/source/src/TinyMDNS)

#---------------------------------------------------------------------------------------
#
# link dir
#
#---------------------------------------------------------------------------------------
LINK_DIRECTORIES(${TINY_ROOT}/target)
LINK_DIRECTORIES(${TINYFX_ROOT}/target)
LINK_DIRECTORIES(${TINYMDNS_ROOT}/target)

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
ADD_SUBDIRECTORY(src)
